---
title: Windows Proxy Execution of .NET Utilities via Scripts
slug: 2024-01-03-proxy-execution-net-utilities
description: Detects the execution of .NET utilities by script processes from unusual locations, indicative of signed binary proxy execution for defense evasion and code execution.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - proxy-execution
  - net-utility
  - defense-evasion
  - execution
  - signed-binary-proxy-execution
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
references:
  - https://www.joesandbox.com/analysis/1817558/0/pdfexecutive
  - https://www.broadcom.com/support/security-center/protection-bulletin/vip-keylogger-spreads-via-multi-org-impersonation-campaign
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.vipkeylogger
rules:
  - title: Detect .NET Utility Execution from Unusual Script Parents
    description: Detects the execution of .NET utilities (aspnet_compiler.exe, InstallUtil.exe, msbuild.exe, regasm.exe, vbc.exe) by script interpreters from suspicious directories.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: Detect .NET Utility Execution with Minimal Command Line
    description: Detects .NET utilities (aspnet_compiler.exe, InstallUtil.exe, msbuild.exe, regasm.exe, vbc.exe) executed with a command line closely matching the image path, which is indicative of proxy execution.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief addresses the abuse of trusted Microsoft .NET binaries as proxies for malicious code execution. Attackers leverage script-based execution (e.g., PowerShell, VBScript, batch files) from atypical or user-writable directories to launch .NET utilities like aspnet_compiler.exe, msbuild.exe, regasm.exe, InstallUtil.exe, and vbc.exe. This method allows threat actors to bypass security controls and blend in with legitimate system activity. Observed activity occurs in environments where endpoint detection and response (EDR) agents are deployed. The lack of command-line variation between the utility's image path and its executed process reinforces the suspicion of proxy execution. This technique has been associated with malware campaigns, including the deployment of VIP Keylogger.

## Attack Chain

1.  An attacker gains initial access to the system (potentially through phishing or exploiting a software vulnerability, although this source does not specify the entry vector).
2.  The attacker drops a malicious script (e.g., a PowerShell script) into a user-writable directory such as C:\\Users\\Public\\ or C:\\Temp\\.
3.  The malicious script executes, and is often obfuscated to evade detection, from the non-standard location.
4.  The script then calls a legitimate .NET utility (e.g., InstallUtil.exe) to execute malicious code.
5.  The .NET utility executes with minimal command-line arguments, often just the executable path itself, to further blend in with legitimate activity.
6.  The .NET utility loads and executes attacker-controlled code, bypassing application control policies.
7.  The malicious code performs actions such as keylogging (as seen with VIP Keylogger), credential theft, or lateral movement.
8.  The attacker achieves their objective, such as data exfiltration or establishing persistent access.

## Impact

Successful exploitation enables attackers to bypass application control and execute arbitrary code, potentially leading to data theft, system compromise, and persistent access. While the number of victims and specific sectors are not detailed in this brief's source, the use of VIP Keylogger as a payload demonstrates the potential for sensitive data exfiltration. Organizations lacking robust endpoint detection capabilities are at significant risk.

## Recommendation

*   Deploy the Sigma rule "Detect .NET Utility Execution from Unusual Script Parents" to identify potential proxy execution attempts based on process relationships and file paths (rule provided below).
*   Investigate any instances of .NET utilities (aspnet_compiler.exe, msbuild.exe, regasm.exe, InstallUtil.exe, vbc.exe) being launched from user-writable directories, especially when the parent process is a script interpreter (batch, CMD, PowerShell, JScript, VBScript, HTML).
*   Monitor process creation events (Sysmon EventID 1 or Windows Event Log Security 4688) for unusual parent-child process relationships involving script interpreters and .NET utilities.
*   Implement application control policies to restrict the execution of .NET utilities from untrusted locations.
