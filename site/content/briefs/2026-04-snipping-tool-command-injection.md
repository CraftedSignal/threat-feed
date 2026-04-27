---
title: 'CVE-2026-32183: Windows Snipping Tool Command Injection Vulnerability'
slug: 2026-04-snipping-tool-command-injection
description: CVE-2026-32183 is a command injection vulnerability in the Windows Snipping Tool that allows a local attacker to execute arbitrary code.
date: "2026-04-14T18:55:15Z"
severities:
  - high
tags:
  - command-injection
  - windows
  - vulnerability
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1105
    technique_name: Ingress Tool Transfer
cves:
  - id: CVE-2026-32183
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32183
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32183
rules:
  - title: Detect Suspicious Snipping Tool Process Creation
    description: Detects suspicious process creation events where the parent process is SnippingTool.exe, indicating potential command injection exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious File Creation by Snipping Tool
    description: Detects suspicious file creation events where the process is SnippingTool.exe, which could indicate malicious payloads being written to disk.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1105
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-32183 describes a command injection vulnerability affecting the Windows Snipping Tool. This vulnerability allows an attacker with local access to execute arbitrary code on a vulnerable system. The vulnerability stems from improper neutralization of special elements within commands processed by the Snipping Tool. While the specific attack vector is not detailed, the nature of command injection suggests that crafted input passed to the tool can be interpreted as commands, leading to…
