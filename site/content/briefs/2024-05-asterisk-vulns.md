---
title: Asterisk and Digium Certified Asterisk Vulnerabilities
slug: 2024-05-asterisk-vulns
description: An authenticated remote attacker can exploit vulnerabilities in Asterisk and Digium Certified Asterisk to achieve arbitrary code execution, denial of service, or information disclosure.
date: "2026-03-25T10:21:05Z"
severities:
  - critical
tags:
  - asterisk
  - voip
  - code-execution
  - dos
  - information-disclosure
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546.003
    technique_name: 'Event Triggered Execution: Windows Management Instrumentation Event Subscription'
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2022-2108
rules:
  - title: Asterisk Configuration Change Detection
    description: Detects suspicious changes to Asterisk configuration files.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1546.003
    data_sources:
      - file_event
      - linux
  - title: Asterisk Suspicious Outbound Connection
    description: Detects Asterisk processes making outbound network connections to unusual ports.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Multiple vulnerabilities exist within Asterisk and Digium Certified Asterisk, potentially allowing a remote, authenticated attacker to perform several malicious actions. These actions include arbitrary code execution, which could lead to complete system compromise, denial-of-service (DoS) attacks, rendering the system unusable, and sensitive information disclosure, potentially leading to further exploitation. The scope of these vulnerabilities encompasses any system running a vulnerable version…
