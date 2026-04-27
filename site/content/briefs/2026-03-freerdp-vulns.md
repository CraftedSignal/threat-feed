---
title: Multiple Vulnerabilities in FreeRDP
slug: 2026-03-freerdp-vulns
description: Multiple vulnerabilities in FreeRDP allow a remote, anonymous attacker to potentially execute arbitrary code, cause a denial of service, cause memory corruption, manipulate data, or disclose sensitive information.
date: "2026-03-30T11:02:08Z"
severities:
  - critical
tags:
  - freerdp
  - vulnerability
  - rdp
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0725
rules:
  - title: Detect Suspicious Network Connection to RDP Port
    description: Detects network connections to the standard RDP port (3389) from unusual source IPs or networks, which may indicate unauthorized access attempts or exploitation of RDP vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect Unusual Process Connecting to RDP Port
    description: Detects processes other than the standard RDP client (mstsc.exe) connecting to the RDP port (3389), potentially indicating malicious activity or lateral movement.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
    techniques:
      - T1021.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Multiple vulnerabilities have been identified in FreeRDP, a free and open-source implementation of the Remote Desktop Protocol (RDP). These vulnerabilities, if exploited, could allow a remote, anonymous attacker to compromise a system running FreeRDP. The vulnerabilities could lead to arbitrary code execution, denial-of-service conditions, memory corruption, data manipulation, and the disclosure of sensitive information. Given the wide deployment of RDP and FreeRDP in various environments…
