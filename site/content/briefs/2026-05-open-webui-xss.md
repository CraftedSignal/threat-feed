---
title: Open WebUI Stored XSS Vulnerability in Banner Component
slug: 2026-05-open-webui-xss
description: Open WebUI versions 0.7.2 and earlier are vulnerable to stored cross-site scripting (XSS) in the banner component due to improper sanitization order, allowing a compromised administrator to inject malicious code, escalate privileges, and potentially steal session tokens from other users, including administrators.
date: "2026-05-14T20:31:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - stored-xss
  - privilege-escalation
  - open-webui
vendors:
  - open-webui
products:
  - open-webui (<= 0.7.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-cqp4-qqvg-3787
  - CVE-2026-45665
rules:
  - title: Detect Open WebUI Stored XSS Payload
    description: Detects CVE-2026-45665 exploitation — identifies stored XSS payloads in Open WebUI banner content.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Open WebUI Malicious Banner Injection
    description: Detects attempts to inject malicious markdown with JavaScript into Open WebUI banners
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

Open WebUI versions 0.7.2 and earlier are susceptible to a stored XSS vulnerability within the banner component. The vulnerability stems from an improper order of sanitization, where DOMPurify is executed before the `marked` library. This flaw allows an attacker with administrator privileges to inject a malicious payload into the global banner. The injected banner is displayed to all users, including Super Administrators, making privilege escalation possible by compromising their sessions. Successful exploitation can bypass existing security mechanisms, allowing for the theft of sensitive information, such as the Super Admin's session token. Version 0.8.0 and later are not affected due to the correction of the sanitization order. This vulnerability impacts all platforms where Open WebUI is deployed. The vulnerability is tracked as CVE-2026-45665.

## Attack Chain

1. An attacker gains unauthorized access to an Open WebUI administrator account.
2. The attacker navigates to the administrative settings panel within Open WebUI.
3. The attacker locates the UI banner configuration section, specifically under **Settings > Interface > UI > Banners**.
4. The attacker crafts a malicious payload using Markdown syntax with a JavaScript injection, such as `[Click for Security Update](javascript:alert(localStorage.token))`, and inputs it into the banner content field.
5. The attacker saves the configuration, which stores the malicious payload in the system.
6. A victim user, especially a Primary Admin, logs into Open WebUI and views the dashboard.
7. The malicious banner is rendered on the dashboard, displaying the crafted link.
8. When the victim clicks the link, the injected JavaScript code executes within the victim's session, potentially exfiltrating sensitive information like session tokens.

## Impact

Successful exploitation of this stored XSS vulnerability allows an attacker to compromise administrator accounts, including those with the highest privileges, on Open WebUI instances version 0.7.2 and earlier. By injecting malicious JavaScript, attackers can steal session tokens, bypass authentication controls, and gain unauthorized access to sensitive data and functionality. The vulnerability could lead to a complete compromise of the Open WebUI system.

## Recommendation

*   Upgrade Open WebUI to version 0.8.0 or later to remediate CVE-2026-45665, where the sanitization order has been corrected.
*   Deploy the Sigma rule "Detect Open WebUI Stored XSS Payload" to identify attempts to inject malicious JavaScript code into banner content.
*   Monitor webserver logs for HTTP requests containing suspicious markdown syntax or JavaScript code in banner-related parameters using the "Detect Open WebUI Malicious Banner Injection" Sigma rule.
