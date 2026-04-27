---
title: Multiple Vulnerabilities in FreeRDP Allow Remote Code Execution and DoS
slug: 2026-04-freerdp-vulns
description: An anonymous remote attacker can exploit multiple vulnerabilities in FreeRDP to potentially execute arbitrary code, cause a denial-of-service condition, manipulate data, disclose confidential information, or perform other unspecified attacks.
date: "2026-04-21T08:04:45Z"
severities:
  - high
tags:
  - freerdp
  - vulnerability
  - rdp
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0880
rules:
  - title: Detect Suspicious RDP Connection from Unusual Source IP
    description: Detects RDP connections originating from IP addresses not commonly associated with RDP traffic to highlight potential external compromise attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect High Volume of Failed RDP Logons
    description: Detects a high volume of failed RDP logon attempts from a single source, indicating potential brute-force or password spraying attacks.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - windows
      - windows
rules_count: 2
---

Multiple vulnerabilities have been identified in FreeRDP, a free remote desktop protocol implementation. An unauthenticated remote attacker can exploit these vulnerabilities to achieve several malicious outcomes. While the specific CVEs and technical details of these vulnerabilities are not disclosed in this brief, the potential impact includes arbitrary code execution, denial-of-service (DoS), data manipulation, and information disclosure. FreeRDP is widely used, so these vulnerabilities have…
