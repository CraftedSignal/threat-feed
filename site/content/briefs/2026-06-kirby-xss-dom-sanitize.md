---
title: 'Kirby: Cross-site scripting (XSS) from incomplete HTML/XML sanitization in Dom::sanitize()'
slug: 2026-06-kirby-xss-dom-sanitize
description: A high-severity cross-site scripting (XSS) vulnerability, tracked as CVE-2026-54002, exists in Kirby CMS versions prior to 4.9.4 and between 5.0.0-alpha.1 and 5.4.3, allowing authenticated Panel users to inject malicious markup into `writer` or `list` fields or via `Sane` API-dependent custom code, leading to stored XSS and potential privilege escalation.
date: "2026-06-18T15:25:22Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Authenticated Panel User
tags:
  - xss
  - web-application
  - cms
  - kirby-cms
vendors:
  - Kirby
products:
  - Kirby CMS (<= 4.9.3)
  - Kirby CMS (>= 5.0.0-alpha.1, <= 5.4.3)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: ""
references:
  - https://github.com/advisories/GHSA-wr9h-4r83-f4v6
rules:
  - title: Detect CVE-2026-54002 XSS Injection in Kirby Panel
    description: Detects CVE-2026-54002 exploitation attempts by identifying common XSS patterns in HTTP POST requests targeting Kirby CMS Panel content editing endpoints.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.007
      - T1547
    data_sources:
      - webserver
  - title: Detect Suspect HTML/SVG File Upload with XSS Payload
    description: Detects attempts to upload HTML or SVG files containing known XSS payloads, potentially exploiting CVE-2026-54002 via custom code using the Sane API for file sanitization.
    platform: sigma
    severity: high
    tactics:
      - execution
      - impact
    techniques:
      - T1059.007
      - T1565
    data_sources:
      - webserver
rules_count: 2
---

A high-severity cross-site scripting (XSS) vulnerability, identified as CVE-2026-54002, affects Kirby CMS versions prior to 4.9.4 and between 5.0.0-alpha.1 and 5.4.3. This flaw stems from incomplete HTML/XML sanitization within the `Dom::sanitize()` method, which is integral to the platform's content processing, including `writer` and `list` fields, and `Sane` API functions. An authenticated Panel user can exploit this by injecting malicious markup as children of unknown HTML/XML tags. The `Dom::sanitize()` method fails to correctly sanitize these unwrapped child nodes, allowing the malicious content to be stored and subsequently executed as JavaScript in the browser of other users, including administrators, when they view the affected content in the Panel or on the site frontend. This creates a risk of privilege escalation and other client-side attacks.

## Attack Chain

1.  An authenticated attacker logs into the Kirby CMS Panel with legitimate credentials.
2.  The attacker navigates to an editable content field, such as a `writer` or `list` field, or interacts with a custom plugin using the `Sane` API functions (`$dom->sanitize()`, `Sane::sanitizeFile()`, etc.).
3.  The attacker crafts and injects malicious markup, specifically including JavaScript code (e.g., `<script>alert('XSS')</script>`) as children of an unknown HTML/XML tag (e.g., `<foo><script>alert(1)</script></foo>`).
4.  The Kirby backend processes the submitted content, invoking the vulnerable `Dom::sanitize()` method.
5.  Due to the flaw, `Dom::sanitize()` unwraps the unknown parent tag but fails to sanitize the malicious child nodes, allowing the JavaScript payload to be saved unsanitized into the content data.
6.  Another user, potentially a higher-privileged administrator, accesses the Panel or frontend page where the maliciously injected content is displayed.
7.  The victim's web browser renders the unsanitized content, leading to the execution of the injected JavaScript within their session context.
8.  The executed script can steal session cookies, perform unauthorized actions via Kirby's API (e.g., privilege escalation), redirect the user, or deface the interface, compromising the victim's account and potentially the entire CMS.

## Impact

The vulnerability poses a significant risk to affected Kirby CMS installations, particularly those with multiple authenticated users where some may be untrusted or malicious. Successful exploitation allows for stored XSS, meaning the injected JavaScript persists and executes each time the compromised content is viewed. This can lead to privilege escalation, enabling lower-privileged authenticated users to escalate their access by compromising higher-privileged user sessions (e.g., administrators). The impact can range from session hijacking, data exfiltration through unauthorized API calls to Kirby's backend, to defacement or other client-side attacks affecting any user viewing the malicious content. The advisory notes that content stored before patching may still contain malicious payloads, emphasizing the persistent nature of the threat.

## Recommendation

*   **Patch CVE-2026-54002**: Immediately update Kirby CMS to version 4.9.4, 5.4.4, or a later release to remediate the sanitization flaw.
*   **Review and Re-sanitize Content**: If untrusted authenticated users had access to the Kirby Panel on a security-critical site, review and re-sanitize all existing content that may have passed through affected fields (e.g., `writer`, `list` fields, or custom code using `Sane` API) for potential malicious payloads.
*   **Deploy Sigma Rule for XSS Attempts**: Deploy the `Detect CVE-2026-54002 XSS Injection in Kirby Panel` Sigma rule to your webserver logs (category `webserver`) to identify attempts to inject XSS payloads into Kirby content fields.
*   **Implement WAF/API Security**: Implement a Web Application Firewall (WAF) or API security gateway to block requests containing known XSS patterns targeting CMS editing endpoints, acting as an additional layer of defense.
