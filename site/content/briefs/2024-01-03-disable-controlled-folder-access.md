---
title: Windows Defender Controlled Folder Access Disabled via Registry Modification
slug: 2024-01-03-disable-controlled-folder-access
description: This analytic detects a Windows registry modification that disables the Windows Defender Controlled Folder Access feature, potentially allowing attackers to bypass a key security control and gain unauthorized access to sensitive files.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - registry-modification
  - windows-defender
vendors:
  - Microsoft
products:
  - Windows Defender
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://x.com/malmoeb/status/1742604217989415386?s=20
  - https://github.com/undergroundwires/privacy.sexy
rules:
  - title: Registry Modification Disabling Controlled Folder Access
    description: Detects a modification to the registry that disables Windows Defender Controlled Folder Access.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Process Modifying Controlled Folder Access Registry Key
    description: Detects the process that modifies the Controlled Folder Access registry key to disabled.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

This brief focuses on the detection of a specific defense evasion technique: disabling Windows Defender Controlled Folder Access (CFA) through registry modification. This is a significant threat because CFA is designed to protect critical folders from unauthorized access, including ransomware attacks. The detection logic monitors changes to the `EnableControlledFolderAccess` registry setting. While specific campaigns are not mentioned, this technique is often employed by threat actors to weaken defenses prior to malware deployment or data exfiltration. The observed activity involves setting the registry value data to "0x00000000", effectively disabling the feature. Successful execution of this technique dramatically increases the risk of successful ransomware attacks and unauthorized data modification.

## Attack Chain

1.  Initial access to the system is achieved through unknown means (e.g., compromised credentials, exploitation of a vulnerability).
2.  The attacker gains elevated privileges, such as administrator rights, required to modify the registry.
3.  The attacker uses a tool like `reg.exe` or PowerShell to modify the registry key `*\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access\EnableControlledFolderAccess`.
4.  The `EnableControlledFolderAccess` registry value is set to "0x00000000", disabling the Controlled Folder Access feature.
5.  The attacker deploys malware or ransomware without the protection of Controlled Folder Access.
6.  Malware gains unauthorized access to protected folders.
7.  Sensitive files are encrypted or exfiltrated.
8.  The attacker achieves their objective, such as data encryption for ransom or data theft.

## Impact

Successful disabling of Controlled Folder Access can have severe consequences. Systems become vulnerable to ransomware attacks and unauthorized modification of sensitive data. Organizations may experience data loss, financial losses due to ransom payments, reputational damage, and regulatory fines. The number of affected systems can range from a single workstation to an entire network, depending on the scope of the attack. Industries that rely heavily on sensitive data, such as healthcare, finance, and legal, are particularly at risk.

## Recommendation

*   Deploy the Sigma rule `Registry Modification Disabling Controlled Folder Access` to your SIEM to detect this specific registry modification.
*   Enable Sysmon EventID 13 to collect the necessary registry modification events for the Sigma rule to function.
*   Investigate any detected instances of `EnableControlledFolderAccess` being set to "0x00000000", as this is not a common legitimate action.
*   Review and harden Group Policy settings related to Windows Defender to prevent unauthorized disabling of security features.
