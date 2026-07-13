---
title: NukeViet CMS Stored Cross-Site Scripting Vulnerability
slug: 2026-07-nukeviet-xss
description: A stored cross-site scripting (XSS) vulnerability, CVE-2026-49259, exists in NukeViet CMS versions 4.x through 4.5.08, including the 'composer/nukeviet/nukeviet' package prior to version 4.5.09, which allows a low-privileged authenticated user to inject JavaScript into their profile's display name fields that executes in the browser of any visitor, including administrators, who clicks the 'Reply' link on a comment posted by the attacker, leading to arbitrary JavaScript execution, administrative session hijacking, credential phishing, and data exfiltration.
date: "2026-07-13T17:27:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-vulnerability
  - cms
  - nukeviet
  - stored-xss
vendors:
  - NukeViet
products:
  - NukeViet CMS < 4.5.09
  - composer/nukeviet/nukeviet < 4.5.09
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The payload executes in the browser of any visitor
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Privilege escalation via admin session hijacking
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-w2w5-w2pw-r929
rules:
  - title: Detects CVE-2026-49259 Exploitation Attempt - NukeViet Profile XSS Injection
    description: Detects CVE-2026-49259 exploitation attempts - injection of JavaScript payloads into NukeViet CMS user profile name fields via POST requests to the editinfo endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.007
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A high-severity stored cross-site scripting (XSS) vulnerability, tracked as CVE-2026-49259, impacts NukeViet CMS versions 4.x through 4.5.08, as well as the 'composer/nukeviet/nukeviet' package prior to version 4.5.09. This flaw allows a low-privileged authenticated user to inject and store JavaScript payloads within their profile's `first_name` and `last_name` display name fields. The vulnerability stems from improper neutralization of input during web page generation, specifically the insufficient JavaScript-context escaping of user-controlled data interpolated into an inline `onclick` handler within comment templates. When any visitor, including site administrators, interacts with the "Reply" link on a comment posted by the attacker, the stored JavaScript payload executes in their browser. This can lead to significant impact, including administrative session hijacking, credential phishing, and sensitive data exfiltration. The issue is exacerbated by default configurations where CAPTCHA for logged-in users is disabled and comments are published immediately without moderation.

## Attack Chain

1. An attacker, as a low-privileged authenticated user, logs into the NukeViet CMS.
2. The attacker navigates to their user profile settings page, accessible via `/index.php?nv=users&op=editinfo`.
3. The attacker injects a JavaScript payload (e.g., `a');alert(document.domain);//`) into their `first_name` or `last_name` profile field.
4. NukeViet CMS processes and stores this input, applying HTML entity encoding (e.g., `a&#039;&#41;;alert&#40;document.domain&#41;;&#x002F;&#x002F;`) via `Request::_get_title()` with `$specialchars = true`.
5. The attacker posts a comment on any NukeViet CMS page. The comment rendering template, `themes/default/modules/comment/comment.tpl`, embeds the attacker's display name (`{COMMENT.post_name}`) within an `onclick` JavaScript handler without sufficient JavaScript-context escaping.
6. A victim, such as an administrator, navigates to the page containing the attacker's comment and clicks the "Reply" link associated with it.
7. The victim's browser first decodes the HTML entities within the `onclick` attribute (e.g., `&#039;` becomes `'`) and subsequently executes the attacker's injected JavaScript payload (e.g., `alert(document.domain)`) in the context of the victim's session.
8. This JavaScript execution allows the attacker to perform arbitrary actions in the victim's browser, potentially leading to administrative session hijacking, credential phishing, or data exfiltration.

## Impact

Successful exploitation of this vulnerability allows an attacker with a regular user account to execute arbitrary JavaScript in the browser of any visitor who clicks the "Reply" link on their comments, including site administrators. This can lead to severe consequences such as administrative session hijacking, enabling the attacker to forge administrative actions like content modification or account manipulation. Attackers can also inject fake login forms for credential phishing or exfiltrate sensitive page content and non-`HttpOnly` cookies from the victim's session. While NukeViet session cookies are `HttpOnly` and thus not directly readable, other attack vectors remain viable.

## Recommendation

* Patch NukeViet CMS to version 4.5.09 or higher immediately to remediate CVE-2026-49259.
* Deploy a web application firewall (WAF) or equivalent security controls to detect and block XSS payloads within HTTP POST requests targeting user profile update endpoints like `/index.php?nv=users&op=editinfo`.
* Implement the provided Sigma rule to detect suspicious injection attempts leveraging common XSS patterns in web server logs or WAF alerts.
* Review web server access logs for `/index.php?nv=users&op=editinfo` `POST` requests containing URL-encoded XSS payloads in query parameters.
* Ensure continuous security auditing of any custom code or modifications to NukeViet CMS templates, specifically focusing on adherence to OWASP's Cross Site Scripting Prevention guidelines, particularly Rule 2 regarding attribute encoding for JavaScript contexts.
