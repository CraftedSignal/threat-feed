---
title: Multiple Vulnerabilities in FreeRDP Allow for DoS and Potential Code Execution
slug: 2026-03-freerdp-vulns
description: A remote, anonymous attacker can exploit multiple vulnerabilities in FreeRDP to cause a denial of service or potentially execute arbitrary program code.
date: "2026-03-24T10:17:27Z"
severities:
  - high
tags:
  - freerdp
  - rdp
  - vulnerability
  - denial-of-service
  - code-execution
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0244
rules:
  - title: Detect Suspicious RDP Connection from Outside the Network
    description: Detects RDP connections initiated from outside the expected network range, potentially indicating unauthorized access attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious Process Creation via RDP Session
    description: Detects the creation of suspicious processes (cmd.exe, powershell.exe) spawned by the RDP service, potentially indicating exploitation or lateral movement.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Multiple vulnerabilities exist within FreeRDP, a free implementation of the Remote Desktop Protocol (RDP). An unauthenticated, remote attacker can exploit these vulnerabilities to achieve a denial-of-service (DoS) condition on a vulnerable system, or potentially gain the ability to execute arbitrary code. While the specific CVEs are not detailed in this brief, the generic nature of RDP exploitation makes it a high-impact concern. This issue came to light on March 24, 2026, and is a potential…
