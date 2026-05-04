---
title: Signed Proxy Execution via MS Work Folders
slug: 2024-01-03-workfolders-control-execution
description: Attackers can abuse Windows Work Folders to execute a masqueraded control.exe file from untrusted locations, potentially bypassing application controls for defense evasion and privilege escalation.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - masquerading
  - windows
vendors:
  - Microsoft
  - Elastic
  - Crowdstrike
  - SentinelOne
products:
  - Windows Work Folders
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - CrowdStrike
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
references:
  - https://docs.microsoft.com/en-us/windows-server/storage/work-folders/work-folders-overview
  - https://twitter.com/ElliotKillick/status/1449812843772227588
  - https://lolbas-project.github.io/lolbas/Binaries/WorkFolders/
rules:
  - title: Detect Suspicious WorkFolders Control Execution
    description: Detects execution of control.exe by WorkFolders.exe from non-standard locations, indicating potential masquerading.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.005
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: Detect WorkFolders.exe Executing control.exe
    description: This rule detects WorkFolders.exe executing control.exe, which may indicate malicious activity if the execution path is unexpected.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Windows Work Folders is a Microsoft file server role that allows users to sync work files between their PCs and a central server. The WorkFolders.exe process, when called, will automatically execute any Portable Executable (PE) named control.exe as an argument before accessing the synced share. Attackers can abuse this functionality by placing a malicious executable renamed to control.exe in a location synced by Work Folders, and then triggering WorkFolders.exe. This can lead to the execution of arbitrary code in a manner that bypasses application control policies, as WorkFolders.exe is a signed Microsoft binary. This technique has been observed in the wild and documented by security researchers. This allows attackers to execute code from locations outside the standard Windows directories, evading traditional detection mechanisms.

## Attack Chain

1. An attacker gains initial access to the target system through an unspecified means (e.g., phishing, exploiting a vulnerability).
2. The attacker places a malicious executable and renames it to `control.exe` in a directory accessible to Work Folders.
3. The attacker configures Windows Work Folders to synchronize the directory containing the malicious `control.exe`.
4. The victim system synchronizes with the Work Folders server, copying the malicious `control.exe` to the local machine.
5. The attacker triggers the `WorkFolders.exe` process.
6. `WorkFolders.exe` executes the `control.exe` binary from the synced folder.
7. The malicious `control.exe` executes, performing attacker-defined actions such as establishing persistence, escalating privileges, or deploying additional malware.
8. The attacker achieves code execution in a potentially elevated context, leveraging a signed Microsoft binary (`WorkFolders.exe`) to bypass security controls.

## Impact

Successful exploitation allows attackers to execute arbitrary code on a victim's machine, potentially bypassing application control and other security measures. This can lead to a range of malicious activities, including data theft, system compromise, and lateral movement within the network. Given the legitimate use of Work Folders, identifying malicious executions can be challenging, potentially allowing attackers to maintain a persistent foothold. The lack of specific victim counts or industry targeting details in the source material limits a complete assessment of impact scope.

## Recommendation

*   Monitor process creations where `WorkFolders.exe` is the parent process and `control.exe` is the child process, but `control.exe` is not located in a standard Windows system directory (Sigma rule: "Detect Suspicious WorkFolders Control Execution").
*   Investigate any instances where `control.exe` is executed from unusual or user-writable locations, especially if `WorkFolders.exe` is involved (see Attack Chain step 6).
*   Enable Sysmon process creation logging (Event ID 1) on Windows systems to capture the necessary data for the provided Sigma rules.
*   Review the Microsoft documentation on Windows Information Protection (WIP) and consider implementing it to encrypt data on PCs using Work Folders.
*   Implement application control policies that restrict the execution of `control.exe` to authorized locations (e.g., `C:\Windows\System32`).
