---
title: Windows Script Execution from Archive File
slug: 2024-01-script-execution-from-archive
description: This rule detects attempts to execute Jscript/Vbscript files from archive files, a common method for delivering malicious scripts by identifying unusual parent-child process relationships where scripting utilities are launched from archive programs, indicating potential exploitation.
date: "2024-01-02T14:22:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - execution
  - archive
  - scripting
  - windows
vendors:
  - Microsoft
  - RARLAB
  - 7-Zip
products:
  - Windows Script Host
  - WinRAR
  - 7-Zip
mitre_ttps:
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
    technique_id: T1204
    technique_name: User Execution
references:
  - https://medium.com/walmartglobaltech/smartapesg-4605157a5b80
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1059/005/
  - https://attack.mitre.org/techniques/T1059/007/
  - https://attack.mitre.org/techniques/T1204/
  - https://attack.mitre.org/techniques/T1204/002/
  - https://attack.mitre.org/tactics/TA0002/
rules:
  - title: Windows Script Execution from Archive
    description: Detects the execution of scripts (VBScript, JScript) from archive files (ZIP, RAR, 7z) by monitoring the parent-child process relationship.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.005
      - T1059.007
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Suspicious WScript Execution from Archive Folders
    description: Detects suspicious script execution from common temporary archive folders using wscript.exe.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.005
      - T1059.007
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers commonly use archive files to deliver malicious scripts, such as Jscript or Vbscript, to victims. This technique allows them to bypass initial security checks and execute code on the target system. This detection focuses on identifying instances where scripting utilities like `wscript.exe` are launched from archive programs like `winrar.exe` or `7zFM.exe`, which could indicate malicious activity. This is especially relevant to environments where users frequently handle archive files, as it helps identify potentially malicious script execution originating from these sources. The rule leverages process creation events to identify these parent-child relationships and flag suspicious activity. The original detection rule was published on 2026-04-20 and has been actively maintained since 2025-08-20 by Elastic.

## Attack Chain

1.  The user downloads an archive file (e.g., ZIP, RAR, 7z) containing a malicious script from a phishing email or compromised website.
2.  The user opens the archive file using an archiving program such as `explorer.exe`, `winrar.exe`, or `7zFM.exe`.
3.  The user extracts the malicious script (e.g., .js, .vbs) to a temporary directory, often within the user's `AppData\Local\Temp` folder.
4.  The user (or an automated process) double-clicks the extracted script file.
5.  `wscript.exe` is launched as a child process of the archiving program, such as `winrar.exe` or `7zFM.exe`, to execute the script.
6.  The malicious script executes commands, potentially downloading further payloads or performing other malicious activities.
7.  The script may establish a connection to a command-and-control (C2) server.
8.  The attacker gains control of the compromised system, potentially leading to data exfiltration or ransomware deployment.

## Impact

Successful exploitation can lead to arbitrary code execution on the victim's machine, potentially resulting in data theft, system compromise, or ransomware infection. The impact can range from individual workstation compromise to wider network breaches, depending on the attacker's objectives and capabilities. Targeted sectors often include organizations where scripting is less monitored, and end-users are more likely to interact with archive files. The use of malicious scripts can bypass traditional security measures, leading to significant damage and disruption.

## Recommendation

*   Enable process creation logging for `wscript.exe` and monitor its command-line arguments to detect suspicious script execution. This helps activate the rules below (log source: `process_creation`).
*   Deploy the Sigma rule "Windows Script Execution from Archive" to your SIEM to detect the execution of Jscript/Vbscript files from archive files (rule: `Windows Script Execution from Archive`).
*   Block the temporary paths listed in the rule query to prevent the execution of scripts from common archive extraction locations. (content: `process.args`)
*   Implement application whitelisting to restrict the execution of unauthorized scripts and scripting utilities, reducing the risk of similar threats in the future (recommendation).
