---
title: Open WebUI Stored Cross-Site Scripting Vulnerability (CVE-2026-56398)
slug: 2026-07-open-webui-stored-xss
description: Open WebUI before version 0.9.5 contains a high-severity stored cross-site scripting (XSS) vulnerability, CVE-2026-56398, in its OAuth authentication flow that allows an authenticated attacker to bypass profile image validation by uploading malicious SVG files, leading to script execution, authentication token theft, and ultimately account takeover for other authenticated users.
date: "2026-07-15T12:22:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-vulnerability
  - account-takeover
  - credential-access
vendors:
  - Open WebUI
products:
  - Open WebUI (< 0.9.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Open WebUI before 0.9.5 contains a stored cross-site scripting vulnerability in the OAuth authentication flow where the picture claim URL MIME type is inferred from file extension rather than Content-Type header, allowing SVG files to bypass the profile image validator and be stored as data URIs.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: enabling script execution in the same origin to steal authentication tokens and achieve account takeover.
    confidence_band: high
cves:
  - id: CVE-2026-56398
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56398
---

A significant stored cross-site scripting (XSS) vulnerability, tracked as CVE-2026-56398, affects Open WebUI versions prior to 0.9.5. This flaw resides within the OAuth authentication flow, specifically concerning the processing of user profile pictures. The core issue stems from the application inferring the MIME type of an uploaded image from its file extension rather than the more reliable Content-Type HTTP header. This misconfiguration allows malicious SVG files, which can contain embedded JavaScript, to bypass the profile image validator. Once a malicious SVG is stored, possibly as a data URI, any authenticated user visiting the profile or an endpoint rendering the image will receive attacker-controlled content. Crucially, this content is delivered with inline disposition and without essential security headers, facilitating the execution of arbitrary JavaScript within the victim's browser, leading to authentication token theft and potential account takeover.

## Attack Chain

1. **Initial Access / Vulnerability Exploitation**: An attacker, leveraging an existing authenticated user account, identifies and targets the stored XSS vulnerability in Open WebUI's OAuth profile picture upload functionality (CVE-2026-56398).
2. **Malicious Content Creation**: The attacker crafts a specially designed SVG file that includes malicious JavaScript code intended to exfiltrate authentication tokens from a victim's browser.
3. **Bypass Validation**: The attacker uploads the malicious SVG file as their profile picture. Due to the vulnerability, Open WebUI incorrectly infers the SVG's MIME type from its file extension, allowing it to bypass the standard profile image validation checks.
4. **Persistence**: The Open WebUI application successfully processes and stores the malicious SVG content, which may be converted into a data URI, permanently associating it with the attacker's user profile.
5. **Victim Interaction**: Another authenticated user (the victim) browses to the attacker's profile page or any other application endpoint that dynamically renders or displays the attacker's profile image.
6. **Client-Side Execution**: The victim's web browser fetches and renders the attacker-controlled SVG content. Because the content is served without adequate security headers and with an inline disposition, the embedded malicious JavaScript executes within the victim's browser session, maintaining the same-origin context.
7. **Credential Access**: The executing JavaScript is designed to access and exfiltrate sensitive authentication tokens (e.g., session cookies, JSON Web Tokens) from the victim's browser, transmitting them to an attacker-controlled server.
8. **Account Takeover**: The attacker utilizes the stolen authentication tokens to hijack the victim's session, thereby gaining unauthorized control over their Open WebUI account and compromising their data and functionality.

## Impact

The successful exploitation of CVE-2026-56398 leads to severe consequences, primarily focusing on credential theft and account takeover. Attackers can gain complete control over compromised Open WebUI accounts by stealing authentication tokens, which can then be used to access sensitive information, modify user data, or interact with the platform as the victim. The broad nature of stored XSS vulnerabilities means that any authenticated user viewing the attacker's profile can be affected, posing a significant risk to the user base of vulnerable Open WebUI instances. While specific victim counts are not available, the potential for widespread impact on user accounts is high, affecting the confidentiality, integrity, and availability of user data within the application.

## Recommendation

* Patch CVE-2026-56398 by upgrading Open WebUI to version 0.9.5 or later immediately.
