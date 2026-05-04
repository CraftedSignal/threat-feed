---
title: Windows Script Execution from Archive File
slug: 2024-01-script-exec-archive
description: This rule identifies attempts to execute Jscript/Vbscript files from an archive file, a common delivery method for malicious scripts on Windows systems.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - execution
  - windows
  - scripting
  - archive
vendors:
  - Elastic
  - Microsoft
  - SentinelOne
  - Crowdstrike
products:
  - M365 Defender
  - SentinelOne Cloud Funnel
  - Crowdstrike
affected_os:
  - Windows
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
rules:
  - title: Detect Script Execution from Archive
    description: Detects the execution of JScript or VBScript files from archive extraction directories using wscript.exe.
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
  - title: Detect Script Execution from Rar Temporary Folder
    description: Detects the execution of JScript or VBScript files from RAR temporary folders using wscript.exe.
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

Attackers commonly use archive files (ZIP, RAR, 7z) to deliver malicious scripts, such as JScript and VBScript, to Windows systems. This technique allows them to bypass some initial security checks and deliver payloads that can execute arbitrary code. The "Windows Script Execution from Archive" detection identifies instances where Windows Script Host (wscript.exe) is launched from temporary directories containing extracted archive contents. This activity can indicate a user has opened a malicious archive, leading to potential malware execution. This detection focuses on the parent-child process relationship, where explorer.exe, winrar.exe, or 7zFM.exe spawns wscript.exe to execute scripts from the temp directory.

## Attack Chain

1. A user receives a malicious archive file (e.g., ZIP, RAR, 7z) via email or downloads it from a website.
2. The user opens the archive file using a file archiver tool like Explorer, WinRAR, or 7-Zip.
3. The archiver extracts the contents, including a malicious JScript (.js) or VBScript (.vbs) file, to a temporary directory, such as `\Users\*\AppData\Local\Temp\7z*\`.
4. The user (or the archiver tool) inadvertently executes the extracted script using Windows Script Host (wscript.exe).
5. Wscript.exe executes the malicious script, which may perform a variety of actions, such as downloading and executing additional payloads.
6. The script establishes persistence via registry modification, adding a run key to execute upon system startup.
7. The script connects to a command-and-control server to receive further instructions.
8. The attacker gains control of the compromised system and begins lateral movement.

## Impact

A successful attack of this nature can lead to arbitrary code execution on the victim's machine, potentially resulting in data theft, malware installation, or complete system compromise. While the number of affected organizations is not specified, the technique is broadly applicable to any Windows environment where users handle archive files, potentially affecting numerous individuals and organizations across various sectors.

## Recommendation

*   Enable process creation logging with command line arguments to capture the execution of wscript.exe and its arguments.
*   Deploy the Sigma rule "Detect Script Execution from Archive" to your SIEM to identify suspicious script execution patterns.
*   Monitor process activity for wscript.exe and other scripting engines executing from temporary directories.
*   Configure endpoint security solutions to block execution of scripts from common temporary directories.
