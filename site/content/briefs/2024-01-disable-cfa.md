---
title: Windows Defender Controlled Folder Access Disabled via Registry Modification
slug: 2024-01-disable-cfa
description: An attacker modifies the Windows registry to disable Windows Defender Controlled Folder Access, a defense evasion technique that weakens protections against unauthorized access and ransomware.
date: "2024-01-03T14:30:00Z"
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
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
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
  - title: Windows Defender Controlled Folder Access Disabled
    description: Detects when Windows Defender Controlled Folder Access is disabled via registry modification.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Process Modifying CFA Registry Key
    description: Detects the process responsible for modifying the Windows Defender Controlled Folder Access registry key.
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

This analytic detects a modification in the Windows registry that disables the Windows Defender Controlled Folder Access (CFA) feature. The detection leverages Sysmon Event ID 13 to monitor changes to the `EnableControlledFolderAccess` registry setting. Disabling CFA is a significant defense evasion technique because it weakens a key security feature designed to protect critical folders from unauthorized access, including ransomware attacks. This allows attackers to potentially bypass this security measure and access or modify sensitive files. This behavior has been linked to malware such as BlankGrabber Stealer and used to bypass endpoint protection.

## Attack Chain

1. An attacker gains initial access to the system (e.g., through phishing or exploiting a vulnerability).
2. The attacker escalates privileges to gain administrative rights necessary to modify the registry.
3. The attacker uses a script or executable (e.g., PowerShell, `reg.exe`) to modify the registry.
4. The attacker targets the registry key `*\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access\EnableControlledFolderAccess`.
5. The attacker sets the registry value to `0x00000000` to disable Controlled Folder Access.
6. The system no longer protects designated folders from unauthorized access by untrusted applications.
7. The attacker deploys ransomware or exfiltrates sensitive data from previously protected folders.

## Impact

Successful disabling of Controlled Folder Access significantly weakens the endpoint's defenses, leaving critical folders vulnerable to unauthorized access and modification. This can lead to successful ransomware deployment, data theft, and other malicious activities. Without CFA, common attack vectors are unhindered, increasing the likelihood of data breaches and system compromise.

## Recommendation

*   Enable Sysmon Event ID 13 to monitor registry modifications, specifically changes to the `EnableControlledFolderAccess` key, to detect attempts to disable Controlled Folder Access.
*   Deploy the provided Sigma rules to your SIEM to detect registry modifications that disable Controlled Folder Access and tune for your environment.
*   Investigate any detected instances of `EnableControlledFolderAccess` being set to `0x00000000` to determine if the activity is malicious.
*   Review and enforce Group Policy settings to prevent users or processes from disabling Controlled Folder Access.
