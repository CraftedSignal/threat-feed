---
title: VaahCMS OTP Template Cross-Site Scripting and Code Execution
slug: 2026-07-vaahcms-xss
description: VaahCMS versions 2.0.0 through 2.3.4 contain a malicious obfuscated JavaScript payload in OTP email templates that executes unauthorized code in victim browsers, enabling credential theft and DOM manipulation.
date: "2026-07-30T07:19:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - credential-theft
  - web-security
vendors:
  - VaahCMS
products:
  - VaahCMS (2.0.0-2.3.4)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: VaahCMS versions 2.0.0 through 2.3.4 contain a malicious obfuscated JavaScript payload embedded in the Blade template.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: The payload establishes a WebSocket connection to a hardcoded command-and-control endpoint.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1056
    technique_name: Input Capture
    evidence: installs a password-field keylogger using MutationObserver to capture dynamically added inputs
    confidence_band: high
cves:
  - id: CVE-2026-67595
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67595
---

VaahCMS versions 2.0.0 through 2.3.4 are affected by a severe cross-site scripting (XSS) vulnerability involving an obfuscated JavaScript payload embedded directly within the Blade template engine responsible for rendering security OTP emails. When a user or administrator views an affected email in a browser with JavaScript enabled, the malicious script executes in the context of the user's session. The payload is highly sophisticated, utilizing MutationObserver to intercept password inputs as they are typed, scraping sensitive data from active WhatsApp Web sessions, and establishing persistent outbound WebSocket connections to attacker-controlled infrastructure. This compromise allows for full credential exfiltration and the ability to dynamically modify the rendered content of the application interface, presenting a critical risk for internal administrative account takeover.

## Attack Chain

1. Attacker identifies the hardcoded malicious JavaScript payload embedded within the VaahCMS security OTP Blade template files.
2. The application triggers an automated security email (e.g., password reset or OTP verification) containing the malicious template.
3. The victim opens the rendered email content in a web browser, triggering the execution of the obfuscated payload.
4. The payload initializes a MutationObserver object to monitor the DOM for input field additions, specifically targeting password fields.
5. The payload executes scraping logic to extract DOM content from active WhatsApp Web sessions if present in the browser state.
6. The script establishes an outbound WebSocket connection to a pre-defined C2 domain for communication.
7. The attacker issues remote commands via the WebSocket to exfiltrate stolen credentials and DOM data, or to redirect/modify the current page content.

## Impact

The vulnerability allows for unauthenticated remote code execution within the victim's browser context. Successful exploitation leads to the theft of credentials and session data, potentially compromising administrative accounts or sensitive corporate communications handled within the browser. The scope is limited to users or administrators who render the malicious OTP email content in a browser environment, but the impact is high due to the nature of the data targeted (passwords and WhatsApp Web communications).

## Recommendation

Prioritized actions for security teams to mitigate this vulnerability:

- Update VaahCMS installations immediately to a patched version beyond 2.3.4 to remove the malicious template code.
- Audit web server access logs and web application logs for unexpected WebSocket upgrade requests emanating from administrative dashboard endpoints.
- Deploy Content Security Policy (CSP) headers that restrict the execution of inline scripts and define strict, allowlisted sources for WebSocket connections to prevent C2 communication.
- Perform an integrity scan on all application Blade template files to check for obfuscated or unauthorized JavaScript blobs that do not match known-good source code.
