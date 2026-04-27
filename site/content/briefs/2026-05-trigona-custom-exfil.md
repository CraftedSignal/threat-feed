---
title: Trigona Ransomware Employing Custom Data Exfiltration Tool
slug: 2026-05-trigona-custom-exfil
description: Trigona ransomware is using a custom data exfiltration tool named 'uploader_client.exe' to steal data from compromised environments, enhancing speed and evasion.
date: "2026-04-23T19:02:17Z"
severities:
  - high
actors:
  - Trigona
tags:
  - trigona
  - ransomware
  - data exfiltration
  - custom tool
vendors:
  - Microsoft
  - Nirsoft
  - AnyDesk
products:
  - Windows
  - AnyDesk
  - Mimikatz
  - PowerRun
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://www.bleepingcomputer.com/news/security/trigona-ransomware-attacks-use-custom-exfiltration-tool-to-steal-data/
ioc_counts:
  file: 1
rules:
  - title: Detect Trigona Custom Exfiltration Tool Execution
    description: Detects execution of the Trigona custom data exfiltration tool 'uploader_client.exe'.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1071.001
    data_sources:
      - process_creation
      - windows
  - title: Detect PowerRun Execution Followed by Credential Dumping
    description: Detects PowerRun execution followed by Mimikatz execution, indicating potential privilege escalation and credential theft.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Trigona ransomware, initially launched in October 2022, has been observed using a custom command-line tool named "uploader_client.exe" to exfiltrate data from compromised environments. This shift, observed in March 2026, suggests an effort to avoid detection by security solutions that commonly flag publicly available tools like Rclone and MegaSync. Symantec researchers believe this indicates a strategic investment in proprietary malware to maintain a lower profile during critical phases of…
