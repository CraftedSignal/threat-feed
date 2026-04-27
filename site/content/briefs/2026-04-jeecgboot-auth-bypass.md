---
title: JeecgBoot AI Chat Module Authentication Bypass Vulnerability
slug: 2026-04-jeecgboot-auth-bypass
description: JeecgBoot versions 3.9.0 and 3.9.1 are vulnerable to a remote unauthenticated bypass in the AI Chat Module, specifically affecting the JeecgBizToolsProvider.java file, potentially allowing unauthorized access.
date: "2026-04-06T04:16:13Z"
severities:
  - high
tags:
  - jeecgboot
  - authentication-bypass
  - ai-chat-module
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5616
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5616
rules:
  - title: JeecgBoot AI Chat Module Authentication Bypass Attempt
    description: Detects potential attempts to exploit the authentication bypass vulnerability in the JeecgBoot AI Chat Module by monitoring requests to the vulnerable JeecgBizToolsProvider.java file.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: JeecgBoot AI Chat Module Abnormal HTTP Status Code
    description: Detects suspicious activity by monitoring HTTP status codes returned when accessing the JeecgBoot AI Chat Module, indicating a potential error or exploit attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical authentication bypass vulnerability has been identified in JeecgBoot, a low-code development platform, affecting versions 3.9.0 and 3.9.1. The vulnerability resides within the AI Chat Module, specifically impacting the `jeecg-boot/jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/airag/JeecgBizToolsProvider.java` file. An attacker can exploit this flaw remotely to bypass authentication mechanisms, potentially gaining unauthorized access to sensitive functionalities…
