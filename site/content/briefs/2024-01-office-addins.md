---
title: Suspicious Execution via Microsoft Office Add-Ins
slug: 2024-01-office-addins
description: This rule detects suspicious execution of Microsoft Office applications launching Office Add-Ins from unusual paths or with atypical parent processes, potentially indicating an attempt to gain initial access via a malicious phishing campaign.
date: "2024-01-03T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - office-addins
  - phishing
  - initial-access
vendors:
  - Microsoft
  - Logitech
  - Elastic
  - SentinelOne
products:
  - Microsoft Office
  - Microsoft Defender XDR
  - Elastic Defend
  - SentinelOne Cloud Funnel
  - LogiOptions
  - Sidekick.vsto
affected_os:
  - Windows
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
references:
  - https://github.com/Octoberfest7/XLL_Phishing
  - https://labs.f-secure.com/archive/add-in-opportunities-for-office-persistence/
rules:
  - title: Office Add-In Loaded From Suspicious Path
    description: Detects Microsoft Office applications loading add-ins from suspicious paths such as Temp or Downloads.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1137.006
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Office Add-In Loaded By Suspicious Parent
    description: Detects Microsoft Office applications loading add-ins with a suspicious parent process like cmd.exe or powershell.exe.
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
  - title: VSTOInstaller executing uninstall
    description: Detects VSTOInstaller.exe executing with the /Uninstall argument
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    techniques:
      - T1070
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Attackers are increasingly leveraging malicious Microsoft Office Add-Ins to gain initial access and persistence on victim systems. These add-ins, often delivered through phishing campaigns, contain embedded malicious code. This detection identifies unusual execution patterns, such as Office applications (WINWORD.EXE, EXCEL.EXE, POWERPNT.EXE, MSACCESS.EXE, VSTOInstaller.exe) launching add-ins (wll, xll, ppa, ppam, xla, xlam, vsto) from suspicious paths like Temp or Downloads directories, or with atypical parent processes (explorer.exe, OpenWith.exe, cmd.exe, powershell.exe). The detection logic filters out known benign activities to minimize false positives, focusing on anomalies indicative of malicious intent, such as installations of Logitech software. This activity matters because successful exploitation can lead to arbitrary code execution, data theft, and further compromise of the victim's network.

## Attack Chain

1.  A user receives a phishing email containing a malicious Microsoft Office document.
2.  The user opens the document, which prompts them to enable macros or install an add-in.
3.  The malicious add-in (wll, xll, ppa, ppam, xla, xlam, vsto) is downloaded from a remote server or dropped into a suspicious directory, such as %TEMP% or %APPDATA%.
4.  The user executes an Office application (WINWORD.EXE, EXCEL.EXE, POWERPNT.EXE, MSACCESS.EXE), which loads the malicious add-in.
5.  The malicious add-in executes arbitrary code, potentially downloading and executing a second-stage payload.
6.  The add-in may establish persistence by modifying registry keys or creating scheduled tasks.
7.  The attacker gains initial access to the system and can perform reconnaissance, lateral movement, and data exfiltration.
8.  The attacker achieves their objective, which could include data theft, ransomware deployment, or intellectual property theft.

## Impact

A successful attack can lead to complete system compromise, data theft, and potential ransomware deployment. Organizations across all sectors are at risk, particularly those with a high volume of email traffic. The use of malicious Office Add-Ins provides attackers with a persistent foothold within the victim's environment, allowing for long-term data collection and disruption of business operations. This can lead to significant financial losses, reputational damage, and legal liabilities.

## Recommendation

*   Deploy the Sigma rule `Office Add-In Loaded From Suspicious Path` to detect add-ins loaded from temporary or download directories based on `process.args` and `process.name`.
*   Deploy the Sigma rule `Office Add-In Loaded By Suspicious Parent` to detect add-ins loaded by `cmd.exe` or `powershell.exe` based on `process.parent.name`.
*   Investigate any instances of `VSTOInstaller.exe` executing with the `/Uninstall` argument, as this may indicate suspicious activity, correlating with the exclusion rule in the provided query.
*   Monitor for Office applications launching add-ins with parent processes of `explorer.exe` or `OpenWith.exe` using process creation logs and the provided query logic.
*   Implement stricter email filtering to prevent phishing emails containing malicious Office documents from reaching end-users.
