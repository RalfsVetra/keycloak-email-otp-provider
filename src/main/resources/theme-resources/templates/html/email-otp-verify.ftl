<#import "template.ftl" as layout>
<@layout.emailLayout>
  <div style="text-align: center;">
    ${kcSanitize(msg("otpEmailBodyHtml", otp))?no_esc}
  </div>
</@layout.emailLayout>
