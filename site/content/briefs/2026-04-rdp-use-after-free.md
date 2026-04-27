---
title: CVE-2026-32157 - Remote Desktop Client Use-After-Free Vulnerability
slug: 2026-04-rdp-use-after-free
description: CVE-2026-32157 is a use-after-free vulnerability in the Remote Desktop Client that allows an unauthorized attacker to execute code over a network.
date: "2026-04-15T12:00:00Z"
severities:
  - critical
tags:
  - cve-2026-32157
  - use-after-free
  - remote-desktop
  - execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
cves:
  - id: CVE-2026-32157
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32157
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32157
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious RDP Client Process Creation
    description: Detects unusual process creation by the Remote Desktop Client (mstsc.exe) that may indicate exploitation of CVE-2026-32157
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect Outbound Network Connection from RDP Client to Unusual Ports
    description: Detects outbound network connections from mstsc.exe to non-standard ports, which could indicate reverse shell activity after CVE-2026-32157 exploitation.
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

CVE-2026-32157 is a critical use-after-free vulnerability affecting the Remote Desktop Client. This flaw allows an unauthenticated attacker to achieve remote code execution on a vulnerable system simply by interacting with the RDP service over a network. The vulnerability stems from improper memory management within the RDP client, leading to a condition where a program attempts to access memory that has already been freed, potentially resulting in arbitrary code execution. Successful…
