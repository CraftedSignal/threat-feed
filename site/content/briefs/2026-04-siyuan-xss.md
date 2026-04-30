---
title: SiYuan Note Reflected XSS Vulnerability in SVG Processing
slug: 2026-04-siyuan-xss
description: SiYuan Note versions prior to the fix for commit f09953afc57a are vulnerable to reflected cross-site scripting (XSS) via a namespace prefix bypass in the SanitizeSVG function when handling dynamic icons, allowing unauthenticated attackers to execute arbitrary JavaScript in a victim's browser.
date: "2026-04-01T00:30:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - siyuan
  - svg
  - reflected-xss
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-73g7-86qr-jrg3
rules:
  - title: Detect SiYuan SVG XSS Attempt
    description: Detects attempts to exploit the SiYuan SVG XSS vulnerability by identifying requests with namespace-prefixed script tags in the content parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SiYuan SVG XSS Attempt (iframe)
    description: Detects attempts to exploit the SiYuan SVG XSS vulnerability by identifying requests with namespace-prefixed iframe tags in the content parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

SiYuan Note, a note-taking application, is susceptible to a reflected XSS vulnerability in its dynamic icon generation functionality. This flaw, present in versions prior to commit f09953afc57a, arises from an insufficient sanitization of SVG content, specifically failing to account for namespace prefixes in SVG elements. The vulnerability resides in the `/api/icon/getDynamicIcon` endpoint, which is accessible without authentication.  An attacker can exploit this by crafting a malicious SVG payload containing namespaced `<script>` tags (e.g., `<x:script xmlns:x="http://www.w3.org/2000/svg">`), which bypasses the application's XSS mitigation measures. Successful exploitation allows arbitrary JavaScript execution within the context of the victim's SiYuan Note instance, potentially leading to data theft or other malicious activities.

## Attack Chain

1. An attacker crafts a malicious URL targeting the `/api/icon/getDynamicIcon` endpoint with the `type=8` parameter.
2. The crafted URL includes a `content` parameter containing a specially crafted SVG payload. This SVG payload leverages a namespace prefix to bypass the `SanitizeSVG` function's intended filtering, e.g., `%3C%2Fx%3Ascript%20xmlns%3Ax%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%3Ealert%28document.domain%29%3C%2Fx%3Ascript%3E`.
3. The victim, either unknowingly or through social engineering, opens the malicious URL in their browser.
4. The SiYuan server processes the request without proper sanitization, inserting the attacker-controlled content into the SVG, and serves the response with `Content-Type: image/svg+xml`.
5. The browser's XML parser interprets the namespace prefix, resolving it to the SVG namespace, and executes the embedded JavaScript code.
6. The JavaScript code executes within the security context of the SiYuan application (`http://<siyuan-host>:6806`), due to `Access-Control-Allow-Origin: *`.
7. The attacker's script can now interact with the SiYuan API using the victim's session cookies.
8. The attacker can perform actions such as reading notes, exporting data, or modifying settings without authentication.

## Impact

This vulnerability poses a significant risk to SiYuan Note users, particularly those whose instances are reachable on a local network. An attacker could potentially compromise sensitive information, manipulate user data, or gain unauthorized access to the application. The ease of exploitation and the absence of authentication requirements make this vulnerability particularly dangerous. Because SiYuan sets `Access-Control-Allow-Origin: *` and the script runs same-origin, it can call any API endpoint using the victim's existing session cookies, including endpoints to read all notes, export data, or modify settings.

## Recommendation

*   Upgrade SiYuan Note to a version that includes the fix for commit f09953afc57a to remediate the vulnerability.
*   Deploy the Sigma rule "Detect SiYuan SVG XSS Attempt" to identify potential exploitation attempts in web server logs.
*   Monitor web server logs for requests to `/api/icon/getDynamicIcon` containing SVG payloads with namespace-prefixed script tags, as demonstrated in the PoC.
*   Consider implementing a Content Security Policy (CSP) on the SiYuan server to restrict the execution of inline JavaScript.
