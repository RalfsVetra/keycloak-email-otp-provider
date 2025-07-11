<#import "template.ftl" as layout>
<@layout.emailLayout>
  <div style="text-align: center;">
    ${kcSanitize(msg("otpEmailBodyHtml", otp, expirationInMinutes))?no_esc}
  </div>
</@layout.emailLayout>
