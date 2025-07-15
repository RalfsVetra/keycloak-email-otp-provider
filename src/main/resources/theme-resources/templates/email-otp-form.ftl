<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
  <#if section = "form">
    <form action="${url.loginAction}" method="post">
      <#assign userEmail = userEmail!"">
      <#assign expirationInMinutes = expirationInMinutes!30>
      <p>We sent a verification code to: <strong>${userEmail}</strong></p>
      <p>Verification code will expire in <strong>${expirationInMinutes}</strong> minutes.</p>
      <div>
        <label>Enter verification code please:</label>
        <input type="text" name="otp" maxlength="6" />
      </div>
      <div>
        <input type="checkbox" id="marketing_consent" name="marketing_consent" />
        <label for="marketing_consent">Yes, I would like to sign up for the newsletter</label>
      </div>
      <button type="submit" name="action" value="verify">Verify</button>
      <button type="submit" name="action" value="resend">Resend Code</button>
    </form>
  </#if>
</@layout.registrationLayout>

