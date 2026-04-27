---
title: OpenSTAManager Time-Based Blind SQL Injection Vulnerability
slug: 2024-01-openstamanager-sqli
description: OpenSTAManager versions before 2.10.2 are susceptible to time-based blind SQL injection via the 'options[stato]' GET parameter, allowing authenticated attackers to extract sensitive database information.
date: "2026-04-02T14:16:26Z"
severities:
  - high
tags:
  - openstamanager
  - sqli
  - cve-2026-28805
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28805
rules:
  - title: Detect OpenSTAManager SQL Injection Attempt
    description: Detects potential SQL injection attempts in OpenSTAManager by monitoring requests with SQL-related keywords in the options[stato] parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenSTAManager Time-Based SQL Injection
    description: Detects potential time-based SQL injection attempts in OpenSTAManager by monitoring requests with SQL-related keywords and SLEEP function in the options[stato] parameter.
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

OpenSTAManager, a management software for technical assistance and invoicing, contains a critical vulnerability that could lead to significant data breaches. Specifically, versions prior to 2.10.2 are vulnerable to Time-Based Blind SQL Injection (CVE-2026-28805) in its AJAX select handlers. The vulnerability exists due to the lack of sanitization, parameterization, or allowlist validation of the 'options[stato]' GET parameter. This allows an authenticated attacker to inject arbitrary SQL…
