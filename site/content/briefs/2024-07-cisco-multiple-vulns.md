---
title: Multiple Vulnerabilities in Cisco Products Allow for Remote Code Execution
slug: 2024-07-cisco-multiple-vulns
description: Multiple vulnerabilities in Cisco ASA, Secure Firewall Threat Defense, IOS, IOS XE, and IOS XR allow a remote attacker to bypass authentication and execute arbitrary code with administrator privileges.
date: "2026-04-24T05:43:56Z"
severities:
  - critical
tags:
  - cisco
  - vulnerability
  - rce
  - authentication-bypass
vendors:
  - Cisco
products:
  - ASA
  - Secure Firewall Threat Defense
  - IOS
  - IOS XE
  - IOS XR
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-2142
rules:
  - title: Detect Cisco Device Configuration Changes via Syslog
    description: Detects unauthorized configuration changes on Cisco devices by monitoring syslog messages, which could indicate exploitation of authentication bypass vulnerabilities and unauthorized access.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - syslog
      - cisco
  - title: Detect Cisco Device Login Failures from Multiple IPs
    description: Detects a high number of failed login attempts from different IP addresses, which may indicate a brute-force attack targeting Cisco device authentication.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - syslog
      - cisco
rules_count: 2
---

A cluster of vulnerabilities affects Cisco ASA (Adaptive Security Appliance), Cisco Secure Firewall Threat Defense, Cisco IOS, Cisco IOS XE, and Cisco IOS XR. A remote attacker, either authenticated or anonymous, can exploit these vulnerabilities to bypass authentication mechanisms and execute arbitrary code with administrator privileges. The broad scope of affected products, ranging from security appliances to core networking infrastructure, makes this a critical issue for organizations…
