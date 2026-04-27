---
title: Multiple Vulnerabilities in Fleet
slug: 2026-03-fleet-vulns
description: Multiple vulnerabilities in Fleet allow an attacker to perform SQL injection, denial of service, bypass security measures, disclose information, and execute arbitrary program code with administrator privileges.
date: "2026-03-30T11:08:57Z"
severities:
  - critical
tags:
  - fleet
  - vulnerability
  - sql-injection
  - denial-of-service
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and System Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021.001
    technique_name: 'Remote Services: RDP'
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021.002
    technique_name: 'Remote Services: SMB/Windows Admin Shares'
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data From Local System
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.004
    technique_name: 'Endpoint Denial of Service: Application Exhaustion'
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0902
rules:
  - title: Detect Suspicious Fleet Processes
    description: Detects suspicious processes spawned by Fleet that may indicate exploitation or malicious activity.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - process_creation
      - windows
  - title: Detect Fleet SQL Injection Attempts
    description: Detects potential SQL injection attempts targeting Fleet based on keywords in web server logs.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Multiple vulnerabilities have been identified in Fleet, a device management platform. These vulnerabilities, if exploited, could allow an attacker to perform a range of malicious activities, including SQL injection attacks, denial-of-service (DoS) attacks, bypassing security measures, disclosing sensitive information, and ultimately executing arbitrary program code with administrator privileges. Successful exploitation poses a significant risk to the confidentiality, integrity, and availability…
