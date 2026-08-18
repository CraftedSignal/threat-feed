---
title: Stored Cross-Site Scripting in Quill Forms WordPress Plugin
slug: 2026-08-quill-forms-xss
description: An unauthenticated Stored Cross-Site Scripting (XSS) vulnerability in the Quill Forms plugin (up to version 5.7.1) allows attackers to inject malicious scripts into web pages, facilitating client-side exploitation.
date: "2026-08-18T06:54:40Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - mdmag
products:
  - Quill Forms | Conversational Multi Step Forms, Surveys & quizzes
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-75091
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75091
  - https://patchstack.com/database/wordpress/plugin/quillforms/vulnerability/wordpress-quill-forms-plugin-5-7-1-cross-site-scripting-xss-vulnerability
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/7ae927b1-401f-4227-9d50-4adde8e95f24?source=cve
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Update Quill Forms plugin to the latest version to address CVE-2026-75091.
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable in all versions up to 5.7.1.
---

The Quill Forms | Conversational Multi Step Forms, Surveys & quizzes plugin for WordPress is affected by a Stored Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-75091. This vulnerability exists in all versions up to and including 5.7.1. The flaw is rooted in insufficient input sanitization and output escaping within the plugin's form handling logic. An unauthenticated attacker can leverage this weakness to inject arbitrary JavaScript into form fields or surveys. When an administrator or another user views the impacted page, the stored malicious script executes within their browser session. This could lead to session hijacking, unauthorized actions on behalf of the victim, or credential theft, posing a significant risk to the integrity of the WordPress site.

## Attack Chain

1. The attacker identifies a WordPress site utilizing the vulnerable Quill Forms plugin version 5.7.1 or earlier.
2. The attacker interacts with a publicly accessible form or survey created by the plugin.
3. The attacker submits a crafted payload containing malicious JavaScript through the input fields that are not properly sanitized.
4. The plugin saves the malicious input into the WordPress database as part of the form submission or configuration data.
5. An unsuspecting user, such as an administrator, accesses the administrative dashboard or a frontend page where the submitted form data is rendered.
6. The web application retrieves the attacker's payload from the database and embeds it into the HTML document without proper output escaping.
7. The victim's browser interprets the injected script as legitimate code and executes it within the context of the site.
8. The attacker achieves their objective, such as stealing session cookies, redirecting the user, or performing unauthorized administrative actions.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary scripts in the browsers of users visiting the impacted pages. If an administrator visits the compromised pages, the attacker could gain administrative control over the WordPress instance. This vulnerability affects any organization using the Quill Forms plugin for collecting user data, surveys, or quizzes, potentially leading to unauthorized data access and site defacement.

## Recommendation

* Immediately update the Quill Forms | Conversational Multi Step Forms, Surveys & quizzes plugin to the latest version patched against CVE-2026-75091.
* Audit existing forms and survey submissions within the WordPress database for anomalous script tags or event handlers (e.g., &lt;script>, onerror, onload).
* Review web server logs for high-frequency or unusual POST requests targeting form submission endpoints if compromise is suspected.
* Implement or strengthen Content Security Policy (CSP) headers to restrict the execution of unauthorized inline scripts.
