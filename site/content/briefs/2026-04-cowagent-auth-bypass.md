---
title: zhayujie chatgpt-on-wechat CowAgent Authentication Bypass Vulnerability (CVE-2026-6126)
slug: 2026-04-cowagent-auth-bypass
description: CVE-2026-6126 is an unauthenticated remote code execution vulnerability in zhayujie chatgpt-on-wechat CowAgent 2.0.4 due to missing authentication in the Administrative HTTP Endpoint.
date: "2026-04-12T11:16:16Z"
severities:
  - high
tags:
  - CVE-2026-6126
  - authentication-bypass
  - web-application
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-6126
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6126
  - https://github.com/zhayujie/chatgpt-on-wechat/issues/2733
  - https://vuldb.com/vuln/356990
rules:
  - title: Detect Attempted Authentication Bypass via Administrative HTTP Endpoint
    description: Detects attempts to access the Administrative HTTP Endpoint without proper authentication, indicating a possible CVE-2026-6126 exploitation attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect CowAgent Version 2.0.4 in User-Agent String
    description: Detects web requests originating from CowAgent version 2.0.4, which is vulnerable to CVE-2026-6126.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-6126, has been discovered in zhayujie chatgpt-on-wechat CowAgent version 2.0.4. This flaw resides within an unspecified function of the Administrative HTTP Endpoint component. Successful exploitation of this vulnerability allows remote attackers to bypass authentication mechanisms, potentially leading to unauthorized access and control over the affected system. The vulnerability is due to missing authentication checks on a critical function. Publicly available…
