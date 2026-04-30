---
title: Windows System Restore Disabled via Registry Modification
slug: 2024-01-03-disable-system-restore
description: Attackers disable Windows System Restore by modifying specific registry keys to hinder recovery efforts after malicious activity.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - impact
  - t1490
  - persistence
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows 10
  - Windows 11
  - Windows Server 2019
  - Windows Server 2022
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1490/T1490.md#atomic-test-9---disable-system-restore-through-registry
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_system_restore.yml
rules:
  - title: Registry Disable System Restore Modified
    description: Detects modification of the registry to disable system restore
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - registry_set
      - windows
  - title: Registry Disable System Restore via reg.exe
    description: Detects disabling system restore via reg.exe command
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may disable the Windows System Restore feature to prevent victims from easily reverting their systems to a clean state after an infection or other malicious activity. This action complicates incident response and remediation efforts, forcing more complex and time-consuming recovery procedures. Disabling system restore is often performed post-compromise to ensure persistence and hinder forensic analysis. This technique can be implemented manually through the registry editor or via automated scripts, making it accessible to a wide range of threat actors.

## Attack Chain

1.  Initial access is gained through various methods (e.g., phishing, exploitation).
2.  The attacker escalates privileges to Administrator or SYSTEM.
3.  The attacker uses `reg.exe` or PowerShell to modify registry keys.
4.  The attacker targets the `HKLM\Software\Policies\Microsoft\Windows NT\SystemRestore\DisableConfig` registry key.
5.  Alternatively, the attacker targets the `HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore\DisableSR` registry key.
6.  The attacker sets the value of the targeted registry key to `DWORD:00000001`.
7.  The attacker confirms the System Restore feature is disabled.
8.  The attacker proceeds with further malicious activities, knowing that recovery is hindered.

## Impact

Disabling System Restore can significantly impede recovery efforts following a cyber incident. Organizations may face longer downtimes and increased costs associated with manual system reimaging or advanced forensic analysis. The absence of readily available restore points can also lead to data loss if systems are severely damaged or encrypted.

## Recommendation

*   Deploy the Sigma rule `Registry Disable System Restore` to your SIEM to detect malicious attempts to disable System Restore via registry modification.
*   Monitor registry modifications related to System Restore configurations, focusing on the keys `\Policies\Microsoft\Windows NT\SystemRestore` and `\Microsoft\Windows NT\CurrentVersion\SystemRestore`, and values set to `DWORD (0x00000001)`.
*   Implement strict access controls to prevent unauthorized modification of registry settings.
