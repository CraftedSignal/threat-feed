---
title: Stored Cross-Site Scripting in MailChimp Subscribe Form Plugin for WordPress
slug: 2026-08-mailchimp-xss
description: An unauthenticated stored XSS vulnerability in the MailChimp Subscribe Form, Optin Builder, PopUp Builder, Form Builder WordPress plugin (up to version 4.3.3) allows attackers to inject arbitrary web scripts into form fields.
date: "2026-08-01T09:50:02Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - umarbajwa
products:
  - MailChimp Subscribe Form, Optin Builder, PopUp Builder, Form Builder
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: The MailChimp Subscribe Form, Optin Builder, PopUp Builder, Form Builder plugin for WordPress is vulnerable to Stored Cross-Site Scripting via Form Field Values.
    confidence_band: high
cves:
  - id: CVE-2026-15052
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15052
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/c3d2425e-69e5-4efe-bbc6-0ef121e74341
rules:
  - title: Detect CVE-2026-15052 Stored XSS Attempt
    description: Detects suspicious HTTP POST requests containing common XSS vectors directed at WordPress plugin form submission endpoints.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

The 'MailChimp Subscribe Form, Optin Builder, PopUp Builder, Form Builder' plugin for WordPress, developed by umarbajwa, contains a high-severity stored Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-15052. The flaw exists in all versions up to and including 4.3.3 and stems from improper input sanitization and output escaping within the plugin's form handling logic. An unauthenticated attacker can supply malicious JavaScript payloads via form fields. These scripts are subsequently stored in the database and executed in the browser of any user who views the page where the form results or data are rendered. This vulnerability poses a significant risk to site administrators and users, as it could facilitate session hijacking, unauthorized actions on behalf of users, or the redirection of visitors to malicious domains.

## Attack Chain

1. Attacker identifies a WordPress site utilizing the vulnerable MailChimp Subscribe Form, Optin Builder, PopUp Builder, Form Builder plugin (version 4.3.3 or earlier).
2. Attacker crafts a malicious JavaScript payload intended for execution in a victim's browser context.
3. Attacker submits the crafted payload through a public-facing input field provided by the plugin.
4. The plugin fails to sanitize the input before committing the data to the WordPress database.
5. The plugin serves the stored, unsanitized input to users (e.g., in an administrative dashboard or public submission view).
6. The victim's browser interprets the stored data as executable script rather than plain text.
7. The attacker's script executes in the context of the victim's session, potentially allowing unauthorized data access or session theft.

## Impact

Successful exploitation of CVE-2026-15052 allows unauthenticated attackers to execute arbitrary JavaScript within the context of the affected WordPress site. This can lead to account takeover if an administrator views the injected content, unauthorized modifications to site content, or the persistent redirection of site visitors to external malicious sites. Given the prevalence of WordPress, this vulnerability impacts any organization currently running versions 4.3.3 or lower of this specific plugin.

## Recommendation

- Update the 'MailChimp Subscribe Form, Optin Builder, PopUp Builder, Form Builder' plugin to a version greater than 4.3.3 immediately.
- If an update is not immediately available, disable the plugin to prevent further exploitation until a patch is applied.
- Review WordPress access logs for anomalous POST requests to the plugin's form submission endpoints containing script-like characters (e.g., &lt;script>, onload=, onerror=).
- Implement a strong Content Security Policy (CSP) to mitigate the impact of XSS attacks by restricting the sources from which scripts can be executed.
