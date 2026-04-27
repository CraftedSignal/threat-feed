---
title: GIMP Multiple Vulnerabilities Allow Code Execution
slug: 2026-04-gimp-code-execution
description: A remote, anonymous attacker can exploit multiple vulnerabilities in GIMP to execute arbitrary program code, potentially leading to system compromise.
date: "2026-04-21T08:09:06Z"
severities:
  - critical
tags:
  - gimp
  - code-execution
  - vulnerability
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0750
rules:
  - title: Detect Suspicious GIMP Child Processes
    description: Detects suspicious child processes spawned by GIMP, indicating potential code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Detect GIMP Outbound Network Connection
    description: Detects outbound network connections from GIMP that are not typical, indicating potential compromise.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The German BSI has issued a security advisory regarding multiple vulnerabilities in GIMP (GNU Image Manipulation Program). An anonymous, remote attacker can exploit these vulnerabilities to achieve arbitrary code execution on a vulnerable system. The specific version(s) of GIMP affected are not detailed in the advisory, nor are the specific vulnerabilities (CVEs). However, the high-level threat is clear: unpatched GIMP installations are susceptible to remote compromise. Defenders should…
