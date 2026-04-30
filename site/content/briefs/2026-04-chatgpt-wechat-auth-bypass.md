---
title: zhayujie chatgpt-on-wechat CowAgent Authentication Bypass (CVE-2026-6129)
slug: 2026-04-chatgpt-wechat-auth-bypass
description: CVE-2026-6129 is a critical vulnerability in zhayujie chatgpt-on-wechat CowAgent up to version 2.0.4, allowing remote attackers to bypass authentication via manipulation of the Agent Mode Service.
date: "2026-04-12T20:16:19Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-6129
  - authentication-bypass
  - chatgpt-on-wechat
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6129
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6129
  - https://github.com/zhayujie/chatgpt-on-wechat/issues/2741
  - https://vuldb.com/vuln/356992
iocs:
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect ChatGPT WeChat CowAgent Authentication Bypass Attempt
    description: Detects potential exploitation attempts of CVE-2026-6129 by monitoring web server logs for suspicious requests targeting the Agent Mode Service.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect ChatGPT WeChat CowAgent Unauthenticated Access
    description: Detects unauthenticated access attempts to critical functions within the ChatGPT WeChat CowAgent application.
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

A critical authentication bypass vulnerability, CVE-2026-6129, has been identified in zhayujie chatgpt-on-wechat CowAgent versions up to 2.0.4. This flaw resides within the Agent Mode Service component and enables unauthenticated remote attackers to execute unauthorized actions by manipulating requests. The vulnerability stems from missing authentication checks, allowing malicious actors to potentially gain unauthorized access and control over affected systems. Exploit code is publicly available, increasing the risk of widespread exploitation. The vendor has been notified, but has not yet responded to the report.

## Attack Chain

1.  Attacker identifies a vulnerable instance of zhayujie chatgpt-on-wechat CowAgent running version 2.0.4 or earlier.
2.  Attacker crafts a malicious request targeting the Agent Mode Service.
3.  The malicious request bypasses authentication checks due to the missing authentication vulnerability (CVE-2026-6129).
4.  The Agent Mode Service processes the crafted request without proper authorization.
5.  Attacker gains unauthorized access to sensitive functions and data within the application.
6.  Attacker leverages the gained access to execute arbitrary commands or manipulate application settings.
7.  Attacker potentially escalates privileges within the application.
8.  Attacker achieves full control over the affected chatgpt-on-wechat CowAgent instance.

## Impact

Successful exploitation of CVE-2026-6129 can lead to complete compromise of the chatgpt-on-wechat CowAgent instance. This includes unauthorized access to user data, modification of application settings, and potentially remote code execution. The lack of authentication allows attackers to perform administrative actions without legitimate credentials. The impact is significant, especially if the affected instance handles sensitive information or is integrated with critical systems.

## Recommendation

*   Apply available patches or updates for zhayujie chatgpt-on-wechat CowAgent immediately to remediate CVE-2026-6129.
*   Monitor web server logs for suspicious requests targeting the Agent Mode Service to identify potential exploitation attempts. Deploy the Sigma rule `Detect ChatGPT WeChat CowAgent Authentication Bypass Attempt` to detect exploitation attempts in web server logs.
*   Implement strong authentication mechanisms for all application endpoints, especially those handling sensitive data or administrative functions.
*   Restrict network access to the chatgpt-on-wechat CowAgent instance to only authorized users and systems.
*   Review and audit the application's codebase to identify and address any other potential security vulnerabilities.
