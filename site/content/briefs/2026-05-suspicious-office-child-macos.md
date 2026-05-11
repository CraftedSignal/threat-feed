---
title: Suspicious macOS MS Office Child Process
slug: 2026-05-suspicious-office-child-macos
description: This rule identifies suspicious child processes of Microsoft Office applications on macOS, which often result from exploitation or malicious macros, by detecting unexpected processes like curl, bash, osascript, and python spawned by Office apps, while filtering out false positives related to product version discovery, error reporting, and legitimate software.
date: "2026-05-11T16:08:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - endpoint
  - macos
  - initial_access
  - microsoft_office
vendors:
  - Microsoft
  - Apple
  - ToDesk
  - JumpCloud
  - Elastic
products:
  - Microsoft Word
  - Microsoft Outlook
  - Microsoft Excel
  - Microsoft PowerPoint
  - Microsoft OneNote
  - ToDesk.app
  - JumpCloud Agent
  - Elastic Defend
affected_os:
  - macos
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/initial_access_suspicious_mac_ms_office_child_process.toml
  - https://blog.malwarebytes.com/cybercrime/2017/02/microsoft-office-macro-malware-targets-macs/
rules:
  - title: Detect Suspicious macOS MS Office Child Process - Shell Execution
    description: Detects suspicious shell commands executed as child processes of Microsoft Office applications on macOS, indicative of potential macro-based malware or exploits.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1059.006
      - T1566.001
    data_sources:
      - process_creation
      - macos
  - title: Detect Suspicious macOS MS Office Child Process - Network Utility Execution
    description: Detects suspicious network utilities like curl or nscurl executed as child processes of Microsoft Office applications on macOS, potentially indicating malicious downloads or communication.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1071.001
      - T1566.001
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

This detection rule identifies suspicious child processes spawned by Microsoft Office applications (Word, PowerPoint, Excel, Outlook, and OneNote) on macOS systems. Attackers often exploit Office applications through malicious macros or document vulnerabilities to execute arbitrary code. This technique allows them to gain an initial foothold on the system. The rule focuses on detecting the execution of scripting languages and system utilities such as `curl`, `bash`, `osascript`, and `python` as child processes of Office applications, indicating potential malicious activity. The rule logic incorporates filters to reduce false positives related to legitimate software behavior and system administration tasks. The rule was last updated on 2026/05/07 and requires Elastic Defend for data collection.

## Attack Chain

1.  A user opens a malicious document (e.g., Word, Excel) received via spearphishing (T1566.001).
2.  The document contains a malicious macro or exploits a vulnerability in the Office application (T1203, T1204.002).
3.  Upon execution, the macro or exploit triggers the Office application to execute a shell command (T1059.004).
4.  The shell command executes a scripting interpreter like `/bin/bash` or `/usr/bin/python` to run malicious code (T1059.004, T1059.006).
5.  The malicious code downloads additional payloads or executes system commands using utilities like `curl` or `osascript`.
6.  The attacker gains initial access to the system and can perform further actions such as reconnaissance or persistence.
7.  The attacker may use `plutil` or `PlistBuddy` to modify system configuration files.
8.  The attacker may use `xattr` to remove file quarantine attributes.

## Impact

Successful exploitation can lead to arbitrary code execution, allowing attackers to install malware, steal sensitive information, or perform other malicious activities. The targeted applications are widely used in enterprise environments, making this a potentially high-impact threat. Although the rule does not specify the number of affected organizations or incidents, the widespread use of Microsoft Office applications on macOS means many systems are potentially at risk.

## Recommendation

*   Deploy the provided EQL rule to your Elastic Security environment to detect suspicious child processes of MS Office applications on macOS (rule).
*   Enable Elastic Defend with the "Complete EDR (Endpoint Detection and Response)" configuration setting to ensure required data is collected (setup).
*   Review and tune the rule's filter conditions based on your organization's environment to minimize false positives, paying attention to the processes and arguments listed in the rule query (query).
*   Implement application control policies to restrict the execution of unauthorized scripting languages and utilities to prevent exploitation through Office applications (rule).
*   Educate users about the risks of opening suspicious attachments and enabling macros in Office documents (T1566.001, T1204.002).
