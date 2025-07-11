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

import java.security.MessageDigest;
import java.util.Map;
import java.util.HashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
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
  public static final String PROVIDER_ID = "email-otp-verify";
  private static final Logger logger = Logger.getLogger(EmailOtpVerify.class);
  
  private static final String OTP_FORM = "email-otp-form.ftl";
  private static final String OTP_EMAIL = "email-otp-verify.ftl";

  private static final String OTP_FIELD = "otp";
  private static final String ACTION_FIELD = "action";
  private static final String ACTION_FIELD_RESEND = "resend";
  
  private static final String OTP_KEY = "EMAIL_OTP";
  private static final String OTP_TIMESTAMP_KEY = "EMAIL_OTP_TIMESTAMP";
  private static final String OTP_ATTEMPTS_KEY = "EMAIL_OTP_ATTEMPTS";
  private static final String OTP_EMAIL_RESEND_TIMESTAMP_KEY = "OTP_EMAIL_RESEND_TIMESTAMP";
  
  private static final String NUMBERS = "0123456789";
  private static final int MAX_OTP_ATTEMPTS = 6;
  private static final int OTP_EXPIRY_SECONDS = 1800; // 30 minutes
  private static final int OTP_EMAIL_RESEND_TIMEOUT_SECONDS = 90; // 1 minute and 30 seconds
  private static final int OTP_LENGTH = 6;

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
      challenge = loginFormsProvider.createForm(OTP_FORM);
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
    String action = formData.getFirst(ACTION_FIELD);
    long currentTime = Time.currentTime();

    if (ACTION_FIELD_RESEND.equals(action)) {
      logger.debugf("Re-sending email requested for user: %s", context.getUser().getUsername());
      String otpEmailResendTimestampStr = authSession.getAuthNote(OTP_EMAIL_RESEND_TIMESTAMP_KEY);

      if (!Validation.isBlank(otpEmailResendTimestampStr)) {
        long timestamp = Long.parseLong(otpEmailResendTimestampStr);
        long elapsedSeconds = currentTime - timestamp;

        if (elapsedSeconds <= OTP_EMAIL_RESEND_TIMEOUT_SECONDS) {
          long remainingSeconds = OTP_EMAIL_RESEND_TIMEOUT_SECONDS - elapsedSeconds;
    
          Response challenge = context.form()
              .setError("otpEmailResendTimeout", remainingSeconds)
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

    String attemptsStr = authSession.getAuthNote(OTP_ATTEMPTS_KEY);
    int attempts = attemptsStr != null ? Integer.parseInt(attemptsStr) : 0;

    if (attempts >= MAX_OTP_ATTEMPTS) {
      removeAuthenticationSession(context, authSession);
      Response response = context.form()
          .setError("otpMaxAttemptsExceeded")
          .createErrorPage(Response.Status.TOO_MANY_REQUESTS);
    
      context.challenge(response);
      return;
    }
    
    String submittedOtp = formData.getFirst(OTP_FIELD);
    
    if (Validation.isBlank(submittedOtp)) {
      showError(context, "otpRequired");
      return;
    }

    String storedOtp = authSession.getAuthNote(OTP_KEY);
    String OtpTimestampStr = authSession.getAuthNote(OTP_TIMESTAMP_KEY);

    if (Validation.isBlank(storedOtp) || Validation.isBlank(OtpTimestampStr)) {
      removeAuthenticationSession(context, authSession);
      Response response = context.form()
          .setError("otpProcessingError")
          .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR);
      
      context.challenge(response);
      return;
    }

    long timestamp = Long.parseLong(OtpTimestampStr);
    long elapsedSeconds = currentTime - timestamp;

    if (elapsedSeconds >= OTP_EXPIRY_SECONDS) {
      showError(context, "otpRequestNewCode");
      return;
    }

    if (MessageDigest.isEqual(storedOtp.getBytes(), submittedOtp.getBytes())) {
      context.getUser().setEmailVerified(true);
      clearSessionNotes(authSession);

      context.getEvent().event(EventType.VERIFY_EMAIL)
          .detail(Details.EMAIL, context.getUser().getEmail()).success();
      context.success();
    } else {
      authSession.setAuthNote(OTP_ATTEMPTS_KEY, String.valueOf(attempts + 1));
      showError(context, "otpIncorrect");
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
    return "Verify Email using OTP";
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
      attributes.put("otp", otp);
      long expirationInMinutes = TimeUnit.SECONDS.toMinutes(OTP_EXPIRY_SECONDS);
      attributes.put("expirationInMinutes", expirationInMinutes);
      
      session
          .getProvider(EmailTemplateProvider.class)
          .setAuthenticationSession(authSession)
          .setRealm(realm)
          .setUser(user)
          .send("otpEmailSubject", OTP_EMAIL, attributes);
      event.success();

      if (authSession.getAuthNote(OTP_EMAIL_RESEND_TIMESTAMP_KEY) != null) {
        return context.form()
            .setSuccess("otpEmailSent")
            .createForm(OTP_FORM);
      } else {
        return context.form().createForm(OTP_FORM);
      }
    } catch (EmailException e) {
      event.clone().event(EventType.SEND_VERIFY_EMAIL)
          .detail(Details.REASON, e.getMessage())
          .user(user)
          .error(Errors.EMAIL_SEND_FAILED);
      logger.error("Failed to send verification email", e);
      context.failure(Messages.EMAIL_SENT_ERROR);
      return context.form()
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
        .setError(messageKey)
        .createForm(OTP_FORM);
    context.challenge(challenge);
  }
}
