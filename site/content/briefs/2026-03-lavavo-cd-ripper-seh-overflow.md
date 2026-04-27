---
title: Lavavo CD Ripper 4.20 SEH Buffer Overflow Vulnerability
slug: 2026-03-lavavo-cd-ripper-seh-overflow
description: Lavavo CD Ripper 4.20 is vulnerable to a structured exception handling (SEH) buffer overflow, allowing local attackers to execute arbitrary code by supplying a malicious string in the License Activation Name field leading to arbitrary code execution and a bind shell.
date: "2026-03-23T14:00:00Z"
severities:
  - critical
tags:
  - buffer-overflow
  - seh
  - cve-2019-25615
  - local-privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25615
  - https://lavavo-cd-ripper.jaleco.com/download
  - https://www.exploit-db.com/exploits/46755
  - https://www.lavavosoftware.com
  - https://www.vulncheck.com/advisories/lavavo-cd-ripper-local-seh-buffer-overflow
rules:
  - title: Detect Lavavo CD Ripper Process Creation
    description: Detects the execution of Lavavo CD Ripper, which may indicate exploitation attempts.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - process_creation
      - windows
  - title: Detect Bind Shell on Port 3110
    description: Detects network connections indicative of a bind shell created after successful exploitation.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Lavavo CD Ripper version 4.20 is susceptible to a critical structured exception handling (SEH) buffer overflow vulnerability. This vulnerability allows a local attacker to execute arbitrary code on a targeted system by crafting a malicious string and providing it as the License Activation Name. The vulnerability, identified as CVE-2019-25615, stems from insufficient bounds checking when handling the license activation data. Successful exploitation enables attackers to gain complete control over…
