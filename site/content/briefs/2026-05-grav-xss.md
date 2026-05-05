---
title: Grav CMS Stored XSS Vulnerability Leading to Potential RCE
slug: 2026-05-grav-xss
description: A stored XSS vulnerability exists in Grav Core + Admin Plugin versions before 2.0.0-beta.2, where a low-privileged user can inject malicious code via a crafted tag, potentially leading to the exfiltration of admin session context, bypassing CSRF protections, and escalating to remote code execution (RCE).
date: "2026-05-06T14:00:00Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - grav
  - xss
  - rce
  - webserver
vendors:
  - Grav
products:
  - Grav Core + Admin Plugin (< 2.0.0-beta.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
references:
  - https://github.com/advisories/GHSA-w8cg-7jcj-4vv2
rules:
  - title: Detect Suspicious SVG Tag Injection in Grav CMS
    description: Detects the injection of potentially malicious SVG tags containing onerror event handlers in Grav CMS page content.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect System Info Exfiltration via navigator.sendBeacon
    description: Detects exfiltration of system information using navigator.sendBeacon after XSS exploitation in Grav CMS.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Grav CMS versions prior to 2.0.0-beta.2 are susceptible to a stored XSS vulnerability. A low-privileged user with the ability to create pages can inject arbitrary JavaScript code through a crafted SVG tag. This vulnerability resides in the `system/src/Grav/Common/Security.php` file, specifically in the `detectXss` function, where insufficient input sanitization allows bypassing the intended XSS filter. Successful exploitation can lead to an administrator's session context being compromised, including the `admin_nonce`. This, in turn, enables attackers to bypass CSRF protections and execute arbitrary code on the server. The vulnerability was patched on 2026-04-24 and will be included in version 2.0.0-beta.2.

## Attack Chain

1. A low-privileged user logs into the Grav CMS admin panel.
2. The user creates a new page or edits an existing one via the `admin/pages/<page>` endpoint.
3. In the page content, the user injects a malicious SVG tag containing an `onerror` event handler: `<svg><foreignObject><img src=x onerror=eval(atob('...'))></foreignObject></svg>`. The base64 encoded payload fetches the `/grav-admin/admin/config/info` endpoint.
4. The malicious page is saved.
5. A Super Admin user visits the compromised page through the Grav admin panel.
6. The injected JavaScript executes within the Super Admin's browser session.
7. The script fetches the `/grav-admin/admin/config/info` endpoint, which contains sensitive system information and the admin nonce.
8. The script sends the exfiltrated data to an attacker-controlled server via `navigator.sendBeacon`.
9. The attacker uses the exfiltrated `admin_nonce` to perform CSRF attacks and potentially achieve RCE.

## Impact

Successful exploitation of this stored XSS vulnerability can lead to full system compromise. An attacker can leverage the exfiltrated `admin_nonce` to bypass CSRF protection, gain administrative privileges, and ultimately execute arbitrary code on the server. The impact includes potential data breaches, system takeover, and complete loss of confidentiality, integrity, and availability. This issue affects Grav Core + Admin Plugin versions prior to `v1.7.49.5 - Admin v1.10.49.1`. The vulnerability has a CVSS score of 9.0, indicating a critical risk.

## Recommendation

*   Upgrade to Grav CMS version 2.0.0-beta.2 or later to address the vulnerability.
*   Deploy the following Sigma rule to detect the injection of potentially malicious SVG tags in page content using web server logs, looking for `cs-uri-query` containing `<svg` and `onerror`: "Detect Suspicious SVG Tag Injection in Grav CMS".
*   Enable web server logging to monitor for POST requests containing SVG tags with event handlers in the request body via the `cs-uri-query` field.
*   Monitor network traffic for outbound connections from the Grav CMS server to external IPs, especially those initiated by browser processes.
