<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
  <#if section = "form">
    <form action="${url.loginAction}" method="post">
      <#assign userEmail = userEmail!"">
      <p>${kcSanitize(msg("otpVerificationCodeSent", userEmail!''))?no_esc}</p>
      <p>${kcSanitize(msg("otpVerificationCodeExpire"))?no_esc}</p>
      <div>
        <label>${msg("otpVerificationCode")}</label>
        <input type="text" name="email-otp" maxlength="6" placeholder="${msg("otpPlaceholder")}"/>
      </div>
      <div>
        <input type="checkbox" id="marketing_consent" name="marketing_consent" />
        <label for="marketing_consent">${msg("otpSignUpForNewletter")}</label>
      </div>
      <button type="submit">${msg("otpButtonVerify")}</button>
      <button type="submit" name="resend">${msg("otpButtonResendCode")}</button>
    </form>
  </#if>
</@layout.registrationLayout>

