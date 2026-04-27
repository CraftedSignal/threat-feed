---
title: Multiple Vulnerabilities in F5 BIG-IP and F5OS
slug: 2026-03-f5-big-ip-vulns
description: Multiple vulnerabilities in F5 BIG-IP and F5OS allow an attacker to bypass security mechanisms, escalate privileges, cause a denial-of-service condition, perform a cross-site scripting attack, and disclose or manipulate information.
date: "2026-03-30T09:24:10Z"
severities:
  - critical
tags:
  - f5
  - big-ip
  - f5os
  - vulnerability
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1598
    technique_name: Phishing for Information
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1189
    technique_name: Drive-by Reconnaissance
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-2310
rules:
  - title: Detect Suspicious URI Access on F5 BIG-IP
    description: Detects suspicious URI patterns commonly associated with web application attacks targeting F5 BIG-IP systems.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Privilege Escalation via F5 Configuration Utility
    description: Detects attempts to modify sensitive configuration files within the F5 BIG-IP system which can lead to privilege escalation.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Multiple vulnerabilities exist within F5 BIG-IP and F5OS, potentially allowing an attacker to bypass security measures, elevate privileges, trigger denial-of-service (DoS) conditions, execute cross-site scripting (XSS) attacks, and expose or manipulate sensitive information. The specific versions affected are not detailed in this advisory, but defenders should assume all versions are vulnerable until patched. Due to the broad range of potential impacts, these vulnerabilities pose a significant…
