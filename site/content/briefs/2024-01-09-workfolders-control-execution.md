---
title: Signed Proxy Execution via MS Work Folders
slug: 2024-01-09-workfolders-control-execution
description: Adversaries may misuse Windows Work Folders to execute a masqueraded 'control.exe' file from a non-standard location, bypassing application controls and potentially escalating privileges.
date: "2024-01-09T14:22:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - masquerading
  - workfolders
  - windows
vendors:
  - Microsoft
products:
  - Windows Work Folders
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
iocs:
  - type: filename
    value: control.exe
ioc_counts:
  filename: 1
rules:
  - title: Detect Suspicious WorkFolders Control Execution
    description: Detects the execution of control.exe by WorkFolders.exe from a non-standard directory, indicating potential abuse of the Work Folders feature for defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: Detect Control.exe Execution from Non-Standard Path
    description: Detects when control.exe is executed from a path other than the system directories, which could indicate a masquerading attack via WorkFolders.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Windows Work Folders feature, intended for file server synchronization, can be abused to execute arbitrary code. Specifically, Work Folders automatically executes any Portable Executable (PE) named `control.exe` located in the same directory. Attackers can leverage this behavior by placing a malicious `control.exe` file in a Work Folders synced directory. When `WorkFolders.exe` is called, the malicious `control.exe` will be executed, potentially bypassing application control mechanisms. This behavior was publicly discussed in October 2021. This poses a risk to organizations leveraging Work Folders for legitimate purposes, as it provides a pathway for malware execution and potential privilege escalation. The attack is effective on systems where Work Folders are enabled and configured.

## Attack Chain

1. An attacker gains initial access to a system through an external mechanism (e.g., phishing, exploit) and establishes a foothold.
2. The attacker drops a malicious executable renamed as `control.exe` into a directory that is synchronized by Windows Work Folders.
3. The attacker triggers the `WorkFolders.exe` process, either manually or through scheduled task manipulation.
4. `WorkFolders.exe` initiates the file synchronization process, and as part of its normal operation, attempts to execute `control.exe`.
5. Due to the presence of the malicious `control.exe` in the synchronized directory, the attacker's code is executed in the context of `WorkFolders.exe`.
6. The malicious `control.exe` performs post-exploitation activities, such as establishing persistence, escalating privileges, or executing lateral movement.
7. The attacker uses the compromised host to propagate further into the network or exfiltrate sensitive data.

## Impact

Successful exploitation allows attackers to bypass application control solutions and execute arbitrary code. This can lead to privilege escalation, lateral movement, and data exfiltration. The impact is significant for organizations that rely on Work Folders for file synchronization. A successful attack gives the adversary a beachhead inside the environment with the potential to compromise sensitive data or critical systems. The severity depends on the privileges associated with the `WorkFolders.exe` process and the actions performed by the malicious `control.exe`.

## Recommendation

*   Deploy the Sigma rule "Detect Suspicious WorkFolders Control Execution" to your SIEM and tune for your environment. This rule detects `control.exe` execution by `WorkFolders.exe` outside of legitimate system paths.
*   Investigate any execution of `control.exe` by `WorkFolders.exe` where the `control.exe` is not located in `C:\\Windows\\System32` or `C:\\Windows\\SysWOW64`.
*   Monitor file creation events in Work Folders synchronized directories for executables named `control.exe`.
*   Consider disabling Work Folders if it is not actively used within the organization to eliminate the attack vector.
*   Implement Windows Information Protection (WIP) to protect data synced by Work Folders as referenced in the overview section.
