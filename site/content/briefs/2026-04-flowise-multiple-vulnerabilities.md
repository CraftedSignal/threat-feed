---
title: Flowise Multiple Vulnerabilities
slug: 2026-04-flowise-multiple-vulnerabilities
description: Multiple vulnerabilities in Flowise allow an attacker to execute arbitrary code, bypass security measures, disclose information, and manipulate files.
date: "2026-04-24T06:24:08Z"
severities:
  - critical
tags:
  - vulnerability
  - code-execution
  - information-disclosure
  - file-manipulation
products:
  - Flowise
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1145
rules:
  - title: Detect Suspicious Flowise HTTP Requests
    description: Detects suspicious HTTP requests to Flowise that may indicate exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Flowise Log Tampering
    description: Detects attempts to tamper with Flowise log files.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Flowise is susceptible to multiple vulnerabilities that could allow a malicious actor to perform several harmful actions. These vulnerabilities, if successfully exploited, could lead to arbitrary code execution, allowing the attacker to gain control of the system. Furthermore, the attacker could bypass security measures put in place to protect the application and its data. Information disclosure could also occur, potentially exposing sensitive data. Finally, the attacker could manipulate files…
