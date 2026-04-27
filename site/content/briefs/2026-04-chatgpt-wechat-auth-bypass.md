---
title: zhayujie chatgpt-on-wechat CowAgent Authentication Bypass (CVE-2026-6129)
slug: 2026-04-chatgpt-wechat-auth-bypass
description: CVE-2026-6129 is a critical vulnerability in zhayujie chatgpt-on-wechat CowAgent up to version 2.0.4, allowing remote attackers to bypass authentication via manipulation of the Agent Mode Service.
date: "2026-04-12T20:16:19Z"
severities:
  - critical
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

A critical authentication bypass vulnerability, CVE-2026-6129, has been identified in zhayujie chatgpt-on-wechat CowAgent versions up to 2.0.4. This flaw resides within the Agent Mode Service component and enables unauthenticated remote attackers to execute unauthorized actions by manipulating requests. The vulnerability stems from missing authentication checks, allowing malicious actors to potentially gain unauthorized access and control over affected systems. Exploit code is publicly…
