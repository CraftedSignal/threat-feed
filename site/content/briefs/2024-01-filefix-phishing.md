---
title: Potential Execution via FileFix Phishing Attack
slug: 2024-01-filefix-phishing
description: Detects potential execution of Windows commands or downloaded files via the browser's dialog box, where adversaries may use phishing to instruct victims to copy and paste malicious commands for execution.
date: "2024-01-02T18:22:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - execution
  - filefix
  - clickfix
  - windows
vendors:
  - Elastic
  - Microsoft
  - SentinelOne
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://mrd0x.com/filefix-clickfix-alternative/
rules:
  - title: Potential Execution via FileFix Phishing Attack
    description: Detects potential execution of commands via the FileFix phishing technique by monitoring process creation events with specific parent process arguments.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: FileFix Downloaded Executable Execution
    description: Detects execution of executables from the downloads folder with FileFix parent process arguments.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies a specific phishing technique known as "FileFix" or "ClickFix," where attackers craft malicious web pages that instruct victims to copy and paste commands into a browser dialog box, leading to execution of those commands on the victim's system. The attack leverages the browser's file-picker functionality to launch processes, bypassing typical security measures. The detection focuses on identifying processes like PowerShell, curl, and others being launched with parent process arguments indicative of this attack pattern: specifically, processes with parent arguments including `--message-loop-type-ui` and `--service-sandbox-type=none`. This is a high-severity threat due to its potential to bypass security controls and execute arbitrary commands. The rule has been actively maintained and updated by Elastic, with the latest update on May 3, 2026, and is designed to work with Elastic Defend, Microsoft Defender XDR, SentinelOne Cloud Funnel, and Windows Sysmon.

## Attack Chain

1. The victim visits a malicious website that uses the FileFix/ClickFix technique.
2. The website prompts the victim to copy a malicious command to their clipboard.
3. The website uses JavaScript to simulate a file download dialog.
4. The victim pastes the malicious command into the file name field of the dialog box.
5. The victim clicks "Save" or "Open", triggering the execution of the pasted command.
6. The browser launches a process (e.g., powershell.exe, cmd.exe) using the file-picker API.
7. The launched process executes the malicious command, potentially downloading and executing further payloads.
8. The attacker gains a foothold on the system, potentially leading to data exfiltration, ransomware deployment, or other malicious activities.

## Impact

A successful FileFix/ClickFix attack can lead to complete system compromise. Since the attack relies on user interaction, it can bypass traditional security measures. Successful exploitation can result in arbitrary code execution, potentially leading to data theft, malware installation, or system disruption. The severity is high, given the potential for significant damage and the ease with which this technique can be deployed via phishing campaigns. While the exact number of victims is not specified, the broad applicability of this technique makes it a significant threat.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect this activity and tune it for your environment.
*   Enable Sysmon process creation logging with command line arguments to ensure the Sigma rule functions correctly.
*   Monitor process creation events for processes with a parent process having arguments `--message-loop-type-ui` and `--service-sandbox-type=none` launching `pwsh.exe`, `powershell.exe`, `curl.exe`, `msiexec.exe`, `mshta.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe`, `certutil.exe`, or `certreq.exe` to identify potential FileFix/ClickFix attacks.
*   Implement user awareness training to educate users about the risks of copying and pasting commands from untrusted websites.
*   Block execution of processes from the `C:\Users\*\Downloads\` path unless explicitly approved and verified.
