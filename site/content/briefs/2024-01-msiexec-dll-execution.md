---
title: Msiexec Arbitrary DLL Execution
slug: 2024-01-msiexec-dll-execution
description: Adversaries may abuse the msiexec.exe utility to proxy the execution of malicious DLL payloads, bypassing application control and other defenses.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - proxy-execution
  - msiexec
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows 10
  - Windows 11
  - Windows Server 2016
  - Windows Server 2019
  - Windows Server 2022
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/msiexec
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218.007/T1218.007.md
  - https://twitter.com/_st0pp3r_/status/1583914515996897281
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_msiexec_execute_dll.yml
rules:
  - title: Suspicious Msiexec Execute Arbitrary DLL
    description: Detects suspicious execution of msiexec.exe to execute arbitrary DLLs.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1218.007
    data_sources:
      - process_creation
      - windows
  - title: Msiexec Network Connection
    description: Detects msiexec.exe initiating network connections, which is unusual
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Msiexec.exe is the command-line utility for the Windows Installer, commonly used to execute installation packages (.msi). Attackers are known to abuse msiexec.exe to proxy the execution of arbitrary DLLs, a technique that helps bypass application control and evade detection. This approach leverages the trusted nature of msiexec.exe to execute malicious code, making it harder for security tools to identify and block the activity. The abuse of msiexec.exe has been observed in various attack campaigns, highlighting the need for defenders to monitor its usage closely.

## Attack Chain

1. An attacker gains initial access to the target system, often through phishing or exploitation of a vulnerability.
2. The attacker uploads a malicious DLL to the compromised system.
3. The attacker uses msiexec.exe with the `/Y` flag to execute the malicious DLL. This flag is used to trigger DLL execution via msiexec.
4. Msiexec.exe loads and executes the malicious DLL.
5. The malicious DLL performs its intended actions, such as establishing persistence, escalating privileges, or deploying additional malware.
6. The attacker may use the proxy execution through msiexec.exe to evade detection by security tools monitoring process execution.
7. The attacker pivots to other systems or begins data exfiltration.
8. The ultimate objective is often data theft, system compromise, or ransomware deployment.

## Impact

Successful exploitation allows attackers to execute arbitrary code on the targeted system, potentially leading to a full system compromise. This can result in data breaches, financial loss, and reputational damage. The technique is particularly effective at bypassing application control solutions, increasing the likelihood of a successful attack. While specific victim counts are unavailable, the widespread use of Windows Installer makes this a relevant threat across various sectors.

## Recommendation

*   Deploy the Sigma rule `Suspicious Msiexec Execute Arbitrary DLL` to your SIEM to detect the execution of msiexec.exe with the `/Y` flag, indicative of potential malicious DLL execution.
*   Investigate any instances of msiexec.exe executing DLLs from unusual or temporary locations.
*   Implement application control policies to restrict the execution of msiexec.exe to authorized users and legitimate installation processes.
*   Monitor process creation events for msiexec.exe to identify suspicious command-line arguments and parent processes.
