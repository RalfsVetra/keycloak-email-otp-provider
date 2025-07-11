<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
  <#if section = "form">
    <form action="${url.loginAction}" method="post">
      <div>
        <label>Enter verification code please:</label>
        <input type="text" name="otp" maxlength="6" />
      </div>
      <button type="submit" name="action" value="verify">Verify</button>
      <button type="submit" name="action" value="resend">Resend Code</button>
    </form>
  </#if>
</@layout.registrationLayout>

