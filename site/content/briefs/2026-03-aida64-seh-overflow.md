---
title: AIDA64 Business SEH Buffer Overflow Vulnerability (CVE-2019-25631)
slug: 2026-03-aida64-seh-overflow
description: AIDA64 Business 5.99.4900 is vulnerable to a local Structured Exception Handling (SEH) buffer overflow (CVE-2019-25631) allowing attackers to execute arbitrary code by overwriting SEH pointers with malicious shellcode.
date: "2026-03-24T12:16:03Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2019-25631
  - buffer-overflow
  - seh
  - aida64
  - windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1201
    technique_name: Application Control Bypass
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218.011
    technique_name: 'Signed Binary Proxy Execution: MSHTA'
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25631
  - https://www.aida64.com
  - https://www.aida64.com/downloads
  - https://www.exploit-db.com/exploits/46639
  - https://www.vulncheck.com/advisories/aida64-business-seh-buffer-overflow-via-egghunter
rules:
  - title: AIDA64 Suspicious Child Process
    description: Detects suspicious child processes spawned by AIDA64 that could indicate exploitation
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1218.011
    data_sources:
      - process_creation
      - windows
  - title: Detect AIDA64 Making Network Connections
    description: Detects AIDA64 making network connections, which might indicate command and control activity after exploitation.
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

AIDA64 Business version 5.99.4900 is vulnerable to a structured exception handling (SEH) buffer overflow (CVE-2019-25631). A local attacker can exploit this vulnerability to execute arbitrary code with application privileges. The vulnerability stems from insufficient bounds checking when processing the SMTP display name field in the preferences or report wizard functionality. An attacker can inject malicious shellcode, specifically egg hunter shellcode, into this field to overwrite SEH…
