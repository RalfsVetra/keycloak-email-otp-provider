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

import java.util.concurrent.TimeUnit;

public final class OtpConstants {
  private OtpConstants() {
    throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
  }

  // Provider Configuration
  public static final String PROVIDER_ID = "email-otp-verify";
  public static final String DISPLAY_TEXT = "Verify Email using OTP";

  // Template Files
  public static final String OTP_FORM = "email-otp-form.ftl";
  public static final String OTP_EMAIL = "email-otp-verify.ftl";

  // Form Fields
  public static final String OTP_FIELD = "email-otp";
  public static final String RESEND_FIELD = "resend";
  public static final String USER_ATTRIBUTE = "terms_and_conditions";
  public static final String MARKETING_CONSENT = "marketing_consent";

  // Session/Cache Keys
  public static final String MARKETING_CONSENT_IP = "marketing_consent_ip";
  public static final String OTP_KEY = "EMAIL_OTP";
  public static final String OTP_TIMESTAMP_KEY = "EMAIL_OTP_TIMESTAMP";
  public static final String OTP_ATTEMPTS_KEY = "EMAIL_OTP_ATTEMPTS";
  public static final String OTP_EMAIL_RESEND_TIMESTAMP_KEY = "OTP_EMAIL_RESEND_TIMESTAMP";

  // OTP Generation
  public static final int OTP_LENGTH = 6;
  public static final String NUMBERS = "0123456789";

  // Limits and Timeouts
  public static final int MAX_OTP_ATTEMPTS = 6;
  public static final int OTP_EXPIRY_SECONDS = 1800; // 30 minutes
  public static final int OTP_EMAIL_RESEND_TIMEOUT_SECONDS = 60; // 1 minute

  // Message Keys (for consistent error/info message handling)
  public static final String MSG_OTP_REQUIRED = "otpRequired";
  public static final String MSG_OTP_INCORRECT = "otpIncorrect";
  public static final String MSG_OTP_EXPIRED = "otpRequestNewCode";
  public static final String MSG_OTP_EMAIL_SENT = "otpEmailSent";
  public static final String MSG_OTP_MAX_ATTEMPTS = "otpMaxAttemptsExceeded";
  public static final String MSG_OTP_PROCESSING_ERROR = "otpProcessingError";
  public static final String MSG_OTP_EMAIL_RESEND_TIMEOUT = "otpEmailResendTimeout";

  // Email Template Keys
  public static final String EMAIL_SUBJECT_KEY = "otpEmailSubject";
  public static final String EMAIL_OTP_PARAM = "otp";

  // Form Attribute Keys (for template context)
  public static final String ATTR_USER_EMAIL = "userEmail";
}
