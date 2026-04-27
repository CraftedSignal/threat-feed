---
title: Multiple Vulnerabilities in FreeRDP Allow Code Execution and DoS
slug: 2026-03-freerdp-vulns
description: Multiple vulnerabilities in FreeRDP allow a remote attacker to execute arbitrary code or cause a denial-of-service condition.
date: "2026-03-30T11:01:43Z"
severities:
  - critical
tags:
  - freerdp
  - vulnerability
  - code-execution
  - denial-of-service
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0514
rules:
  - title: Detect Suspicious FreeRDP Client Executables
    description: Detects FreeRDP client executables running from unusual locations, which may indicate malicious activity or unauthorized usage.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: Detect FreeRDP Process Making Network Connections
    description: Detects FreeRDP processes establishing network connections, useful for baseline monitoring and identifying potentially malicious connections.
    platform: sigma
    severity: informational
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Multiple vulnerabilities exist within FreeRDP, a free remote desktop protocol implementation. Successful exploitation of these vulnerabilities could allow a remote attacker to achieve arbitrary code execution on the target system or trigger a denial-of-service (DoS) condition, impacting the availability of the service. This advisory highlights the potential risks associated with running unpatched FreeRDP instances. Defenders should promptly investigate and apply available patches or mitigations…
