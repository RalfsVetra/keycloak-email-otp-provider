# Keycloak Email OTP Required Action Provider

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Keycloak](https://img.shields.io/badge/Keycloak-26.0+-red.svg)](https://www.keycloak.org/)
[![Java](https://img.shields.io/badge/Java-21+-orange.svg)](https://openjdk.java.net/)

A comprehensive **email-based OTP (One-Time Password) verification provider** for Keycloak that significantly enhances user registration security by requiring email verification before account activation. Perfect for organizations requiring robust user verification workflows with built-in consent management.

## 🚀 Key Features

### ✉️ **Secure Email OTP Delivery**
- Generates cryptographically secure one-time passwords
- Sends OTP codes directly to user's registered email address

### ⏱️ **Smart Timeout Management**
- Automatic code expiration for enhanced security
- Prevents replay attacks with time-based validation

### 🔐 **Advanced Validation System**
- Real-time OTP code validation
- Input sanitization and security checks
- Comprehensive error handling and user feedback

### 🎨 **Customizable Email Templates**
- Professional, responsive email templates
- Fully customizable HTML/text email formats
- Brand-consistent messaging

### 📋 **Consent Management**
- **Marketing Consent**: GDPR-compliant marketing communication opt-in
- **Terms & Conditions Consent**: Legal agreement acceptance tracking

### 🔄 **User-Friendly Recovery Options**
- **Password Resend Functionality**: Users can request new OTP codes
- Intelligent resend throttling to prevent abuse

### 🛡️ **Security Controls**
- **Maximum Attempt Limits**
- Account lockout protection against brute force attacks
- Rate limiting for OTP generation requests

## 🏗️ Installation

### Prerequisites
- Keycloak 26.0 or higher
- Java 21 or higher
- SMTP server configuration in Keycloak

### Quick Setup

1. **Download the Provider**
   ```bash
   wget https://github.com/RalfsVetra/keycloak-email-otp-provider/releases/download/v2.0.0/com.scandicom-keycloak-email-otp-provider-2.0.0.jar
   ```

2. **Deploy to Keycloak**
   ```bash
   cp com.scandicom-keycloak-email-otp-provider-2.0.0.jar /keycloak/providers/
   ```

3. **Build Keycloak with the new provider**
   ```bash
   cd /keycloak
   bin/kc.sh build
   ```

4. **Configure in Admin Console**
   - Navigate to **Authentication** → **Required Actions**
   - Turn off default "Verify email" 
   - Enable "Verify Email using OTP"
   - Set as default for new users

## ⚙️ Configuration

### Email Template Customization

Create custom email templates in your Keycloak theme:

```
themes/your-theme/email/
├── html/
│   └── email-otp-verify.ftl
└── text/
    └── email-otp-verify.ftl
```

### Form Template Customization

Create custom form template in your Keycloak theme:

```
themes/your-theme/login/
├── email-otp-form.ftl
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/RalfsVetra/keycloak-email-otp-provider.git
cd keycloak-email-otp-provider
mvn clean install
```

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/RalfsVetra/keycloak-email-otp-provider/issues)

## 🏷️ Keywords

`keycloak` `otp` `email-verification` `two-factor-authentication` `user-registration` `security` `identity-management` `authentication` `java` `spring-boot` `gdpr-compliance` `consent-management` `enterprise-ready`

---

⭐ **Star this repository** if you find it helpful!

📢 **Follow** for updates on new features and releases.