---
title: Suspicious Execution via Microsoft Office Add-Ins
slug: 2024-01-office-addins
description: This rule identifies suspicious execution patterns where Microsoft Office applications launch add-ins from unusual paths or with atypical parent processes, potentially indicating initial access via a malicious phishing MS Office Add-In.
date: "2024-01-03T18:12:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - office-addins
  - initial-access
  - phishing
vendors:
  - Microsoft
products:
  - Microsoft Word
  - Microsoft Excel
  - Microsoft PowerPoint
  - Microsoft Access
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1137
    technique_name: Office Application Startup
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1129
    technique_name: Shared Modules
references:
  - https://github.com/Octoberfest7/XLL_Phishing
  - https://labs.f-secure.com/archive/add-in-opportunities-for-office-persistence/
  - https://attack.mitre.org/techniques/T1566/
  - https://attack.mitre.org/techniques/T1566/001/
  - https://attack.mitre.org/tactics/TA0001/
  - https://attack.mitre.org/techniques/T1137/
  - https://attack.mitre.org/techniques/T1137/006/
  - https://attack.mitre.org/tactics/TA0003/
  - https://attack.mitre.org/techniques/T1129/
  - https://attack.mitre.org/techniques/T1204/
  - https://attack.mitre.org/techniques/T1204/002/
  - https://attack.mitre.org/tactics/TA0002/
rules:
  - title: Suspicious Office Add-in Execution from Temp Directory
    description: Detects Office applications executing add-ins (wll, xll, ppa, ppam, xla, xlam, vsto) from the Temp directory.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1204.002
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Office Add-in Execution with Unusual Parent Process
    description: Detects Office applications executing add-ins (wll, xll, ppa, ppam, xla, xlam, vsto) with cmd.exe or powershell.exe as the parent process.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1204.002
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: VSTOInstaller executing with URL argument
    description: Detects VSTOInstaller executing with a URL argument.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1204.002
      - T1566.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This detection rule identifies execution of common Microsoft Office applications (WINWORD.EXE, EXCEL.EXE, POWERPNT.EXE, MSACCESS.EXE, VSTOInstaller.exe) to launch an Office Add-In from a suspicious path or with an unusual parent process. The rule leverages process monitoring to detect when these Office applications load add-ins (wll, xll, ppa, ppam, xla, xlam, vsto) from locations like Temp directories, Downloads, or from unusual parent processes such as cmd.exe or powershell.exe. This activity may indicate an attempt to get initial access via a malicious phishing MS Office Add-In. The rule filters out known benign activities, such as Logitech software installations, VSTO uninstalls, and specific Rundll32.exe executions to minimize false positives, focusing on genuine anomalies indicative of malicious intent. The rule was last updated on 2026/04/07.

## Attack Chain

1.  The attacker sends a spearphishing email with a malicious Office document or a link to download one.
2.  The victim opens the malicious Office document (e.g., Word, Excel, PowerPoint).
3.  The Office application executes, triggering the download and execution of a malicious add-in (wll, xll, ppa, ppam, xla, xlam, vsto) from a suspicious location (e.g., %TEMP%, Downloads).
4.  Alternatively, the user may be tricked into manually installing the add-in.
5.  The add-in executes within the context of the Office application (WINWORD.EXE, EXCEL.EXE, POWERPNT.EXE, MSACCESS.EXE).
6.  The malicious add-in performs malicious actions, such as downloading additional payloads, establishing command and control, or exfiltrating data.
7.  The attacker leverages the compromised Office application and add-in for persistence and further exploitation.

## Impact

A successful attack can lead to initial access within the targeted organization. The attacker can then leverage the compromised system for further malicious activities, including data theft, lateral movement, and the installation of ransomware. The use of Office Add-Ins allows attackers to bypass traditional security controls and blend in with legitimate Office activity. Because the rule detects add-in execution, the damage ranges from initial access to lateral movement and persistence depending on the attacker objectives.

## Recommendation

*   Enable process creation logging in Windows via Sysmon or Windows event logging to capture process execution details. This will activate the rules below.
*   Deploy the Sigma rules provided to your SIEM to detect suspicious Office add-in execution and tune the rules for your specific environment.
*   Block execution of Office add-ins from common temporary directories like `%TEMP%` and `Downloads` using application control policies. This mitigates the risk highlighted in the "Attack Chain" section.
*   Regularly review and audit installed Office add-ins to identify and remove any unauthorized or suspicious add-ins.
*   Monitor process execution for unusual parent-child relationships involving Office applications, as highlighted in the Sigma rules and the attack chain.
