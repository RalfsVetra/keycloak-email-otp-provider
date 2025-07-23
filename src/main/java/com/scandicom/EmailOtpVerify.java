/*
 * Copyright 2025 Scandicom SIA. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.scandicom;

import static com.scandicom.OtpConstants.*;
import java.security.MessageDigest;
import java.util.Map;
import java.util.HashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import java.util.Objects;
import java.util.Arrays;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.AuthorizationEndpointBase;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.services.managers.AuthenticationSessionManager;

public class EmailOtpVerify implements RequiredActionProvider, RequiredActionFactory {
  private static final Logger logger = Logger.getLogger(EmailOtpVerify.class);

  @Override
  public void evaluateTriggers(RequiredActionContext context) {
    if (context.getRealm().isVerifyEmail() && !context.getUser().isEmailVerified()) {
      context.getUser().addRequiredAction(PROVIDER_ID);
      logger.debug("User is required to verify email");
    }
  }

  @Override
  public InitiatedActionSupport initiatedActionSupport() {
    return InitiatedActionSupport.SUPPORTED;
  }

  @Override
  public void requiredActionChallenge(RequiredActionContext context) {
    process(context, true);
  }

  private void process(RequiredActionContext context, boolean isChallenge) {
    AuthenticationSessionModel authSession = context.getAuthenticationSession();

    if (context.getUser().isEmailVerified()) {
      context.success();
      clearSessionNotes(authSession);
      return;
    }

    String email = context.getUser().getEmail();
    if (Validation.isBlank(email)) {
      context.ignore();
      return;
    }

    LoginFormsProvider loginFormsProvider = context.form();
    loginFormsProvider.setAuthenticationSession(context.getAuthenticationSession());
    Response challenge;
    authSession.setClientNote(AuthorizationEndpointBase.APP_INITIATED_FLOW, null);
    
    if (!Objects.equals(authSession.getAuthNote(Constants.VERIFY_EMAIL_KEY), email) &&
        !(isCurrentActionTriggeredFromAIA(context) && isChallenge)) {
      String otp = generateOtp();
      authSession.setAuthNote(OTP_KEY, otp);
      authSession.setAuthNote(OTP_TIMESTAMP_KEY, String.valueOf(Time.currentTime()));
      authSession.setAuthNote(Constants.VERIFY_EMAIL_KEY, email);

      EventBuilder event = context.getEvent().clone().event(EventType.SEND_VERIFY_EMAIL)
          .detail(Details.EMAIL, email);

      challenge = sendEmailOtp(context, otp, authSession, event);
    } else {
      challenge = loginFormsProvider
          .setAttribute(ATTR_USER_EMAIL, context.getUser().getEmail())
          .createForm(OTP_FORM);
    }

    context.challenge(challenge);
  }

  private boolean isCurrentActionTriggeredFromAIA(RequiredActionContext context) {
    return Objects.equals(context.getAuthenticationSession()
        .getClientNote(Constants.KC_ACTION), getId());
  }

  @Override
  public void processAction(RequiredActionContext context) {
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    
    if (formData.containsKey(RESEND_FIELD)) {
      handleResendRequest(context, authSession);
      return;
    }

    handleOtpValidation(context, authSession, formData);
  }

  private void handleResendRequest(
      RequiredActionContext context,
      AuthenticationSessionModel authSession) {
    logger.debugf("Re-sending email requested for user: %s", context.getUser().getUsername());
    String otpEmailResendTimestampStr = authSession.getAuthNote(OTP_EMAIL_RESEND_TIMESTAMP_KEY);
    long currentTime = Time.currentTime();

    if (!Validation.isBlank(otpEmailResendTimestampStr)) {
      long timestamp = Long.parseLong(otpEmailResendTimestampStr);
      long elapsedSeconds = currentTime - timestamp;

      if (elapsedSeconds <= OTP_EMAIL_RESEND_TIMEOUT_SECONDS) {
        long remainingSeconds = OTP_EMAIL_RESEND_TIMEOUT_SECONDS - elapsedSeconds;
    
        Response challenge = context.form()
          .setAttribute(ATTR_USER_EMAIL, context.getUser().getEmail())
          .setError(MSG_OTP_EMAIL_RESEND_TIMEOUT, remainingSeconds)
          .createForm(OTP_FORM);
    
        context.challenge(challenge);
        return;
      }
    }

    authSession.setAuthNote(OTP_EMAIL_RESEND_TIMESTAMP_KEY, String.valueOf(currentTime));

    // This will allow user to re-send email again
    context.getAuthenticationSession().removeAuthNote(Constants.VERIFY_EMAIL_KEY);
    process(context, false);
    return;
  }

  private void handleOtpValidation(
      RequiredActionContext context,
      AuthenticationSessionModel authSession,
      MultivaluedMap<String, String> formData) {
    long currentTime = Time.currentTime();
    String attemptsStr = authSession.getAuthNote(OTP_ATTEMPTS_KEY);
    int attempts = attemptsStr != null ? Integer.parseInt(attemptsStr) : 0;

    if (attempts >= MAX_OTP_ATTEMPTS) {
      removeAuthenticationSession(context, authSession);
      Response response = context.form()
          .setAttribute(ATTR_USER_EMAIL, context.getUser().getEmail())
          .setError(MSG_OTP_MAX_ATTEMPTS)
          .createErrorPage(Response.Status.TOO_MANY_REQUESTS);
    
      context.challenge(response);
      return;
    }
    
    String submittedOtp = formData.getFirst(OTP_FIELD);
    
    if (Validation.isBlank(submittedOtp)) {
      showError(context, MSG_OTP_REQUIRED);
      return;
    }

    String storedOtp = authSession.getAuthNote(OTP_KEY);
    String OtpTimestampStr = authSession.getAuthNote(OTP_TIMESTAMP_KEY);

    if (Validation.isBlank(storedOtp) || Validation.isBlank(OtpTimestampStr)) {
      removeAuthenticationSession(context, authSession);
      Response response = context.form()
          .setAttribute(ATTR_USER_EMAIL, context.getUser().getEmail())
          .setError(MSG_OTP_PROCESSING_ERROR)
          .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
      
      context.challenge(response);
      return;
    }

    long timestamp = Long.parseLong(OtpTimestampStr);
    long elapsedSeconds = currentTime - timestamp;

    if (elapsedSeconds >= OTP_EXPIRY_SECONDS) {
      showInfo(context, MSG_OTP_EXPIRED);
      return;
    }

    boolean marketingConsent = formData.containsKey(MARKETING_CONSENT);

    if (MessageDigest.isEqual(storedOtp.getBytes(), submittedOtp.getBytes())) {
      context.getUser().setEmailVerified(true);
      clearSessionNotes(authSession);

      context.getEvent().event(EventType.VERIFY_EMAIL)
          .detail(Details.EMAIL, context.getUser().getEmail()).success();

      context.getUser()
          .setAttribute(USER_ATTRIBUTE, Arrays.asList(Integer.toString(Time.currentTime())));

      if (marketingConsent) {
        context.getUser()
            .setAttribute(MARKETING_CONSENT, Arrays.asList(Integer.toString(Time.currentTime())));
        context.getUser()
            .setAttribute(MARKETING_CONSENT_IP, Arrays.asList(context.getConnection()
                .getRemoteAddr()));
      }
      
      context.success();
    } else {
      authSession.setAuthNote(OTP_ATTEMPTS_KEY, String.valueOf(attempts + 1));
      showError(context, MSG_OTP_INCORRECT);
    }
  }

  @Override
  public void close() {
  }

  @Override
  public RequiredActionProvider create(KeycloakSession session) {
    return this;
  }

  @Override
  public void init(Config.Scope config) {
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
  }

  @Override
  public String getDisplayText() {
    return DISPLAY_TEXT;
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  private Response sendEmailOtp(
      RequiredActionContext context,
      String otp,
      AuthenticationSessionModel authSession,
      EventBuilder event) {
    RealmModel realm = context.getRealm();
    UserModel user = context.getUser();
    KeycloakSession session = context.getSession();

    try {
      Map<String, Object> attributes = new HashMap<>();
      attributes.put(EMAIL_OTP_PARAM, otp);
      
      session
          .getProvider(EmailTemplateProvider.class)
          .setAuthenticationSession(authSession)
          .setRealm(realm)
          .setUser(user)
          .send(EMAIL_SUBJECT_KEY, OTP_EMAIL, attributes);
      event.success();

      if (authSession.getAuthNote(OTP_EMAIL_RESEND_TIMESTAMP_KEY) != null) {
        return context.form()
            .setAttribute(ATTR_USER_EMAIL, context.getUser().getEmail())
            .setSuccess(MSG_OTP_EMAIL_SENT)
            .createForm(OTP_FORM);
      } else {
        return context.form()
            .setAttribute(ATTR_USER_EMAIL, context.getUser().getEmail())
            .createForm(OTP_FORM);
      }
    } catch (EmailException e) {
      event.clone().event(EventType.SEND_VERIFY_EMAIL)
          .detail(Details.REASON, e.getMessage())
          .user(user)
          .error(Errors.EMAIL_SEND_FAILED);
      logger.error("Failed to send verification email", e);
      context.failure(Messages.EMAIL_SENT_ERROR);
      return context.form()
          .setAttribute(ATTR_USER_EMAIL, context.getUser().getEmail())
          .setError(Messages.EMAIL_SENT_ERROR)
          .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  private void removeAuthenticationSession(
      RequiredActionContext context,
      AuthenticationSessionModel authSession) {
    clearSessionNotes(authSession);
    AuthenticationSessionManager authManager =
        new AuthenticationSessionManager(context.getSession());
    authManager.removeAuthenticationSession(context.getRealm(), authSession, true);
  }

  private String generateOtp() {
    return SecretGenerator.getInstance().randomString(OTP_LENGTH, NUMBERS.toCharArray());
  }

  private void clearSessionNotes(AuthenticationSessionModel authSession) {
    authSession.removeAuthNote(OTP_KEY);
    authSession.removeAuthNote(OTP_TIMESTAMP_KEY);
    authSession.removeAuthNote(OTP_ATTEMPTS_KEY);
    authSession.removeAuthNote(OTP_EMAIL_RESEND_TIMESTAMP_KEY);
    authSession.removeAuthNote(Constants.VERIFY_EMAIL_KEY);
  }

  private void showError(RequiredActionContext context, String messageKey) {
    Response challenge = context.form()
        .setAttribute(ATTR_USER_EMAIL, context.getUser().getEmail())
        .setError(messageKey)
        .createForm(OTP_FORM);
    context.challenge(challenge);
  }

  private void showInfo(RequiredActionContext context, String messageKey) {
    Response challenge = context.form()
        .setAttribute(ATTR_USER_EMAIL, context.getUser().getEmail())
        .setInfo(messageKey)
        .createForm(OTP_FORM);
    context.challenge(challenge);
  }
}
