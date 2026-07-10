---
title: Symbolic Link Creation to Shadow Copies for Credential Access
slug: 2024-01-shadow-copy-symlink
description: The creation of symbolic links to shadow copies on Windows systems by processes such as cmd.exe or powershell.exe can indicate an attempt to access sensitive files for credential theft.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - defense-evasion
  - windows
vendors:
  - Microsoft
products:
  - Windows
  - Active Directory
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1006
    technique_name: Direct Volume Access
references:
  - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/mklink
  - https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf
  - https://blog.netwrix.com/2021/11/30/extracting-password-hashes-from-the-ntds-dit-file/
  - https://www.hackingarticles.in/credential-dumping-ntds-dit/
rules:
  - title: Symbolic Link to Shadow Copy Created (Sysmon)
    description: Detects the creation of symbolic links to shadow copy paths using mklink by cmd.exe or powershell.exe via Sysmon event ID 1.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.003
    data_sources:
      - process_creation
      - windows
  - title: Symbolic Link to Shadow Copy Created (Event ID 4656)
    description: Detects the attempt to access a shadow copy via a symbolic link based on event ID 4656.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1003.003
    data_sources:
      - object_access
      - windows
rules_count: 2
---

This activity identifies the creation of symbolic links pointing to shadow copies within a Windows environment. Shadow copies, also known as Volume Shadow Copies, are point-in-time snapshots of volumes that can contain sensitive information, including the Active Directory database (ntds.dit) and other critical system files. An attacker can create a symbolic link to these shadow copies, effectively circumventing file system permissions to access these protected files. This technique allows for offline credential dumping and extraction of password hashes. The activity is typically conducted using command-line tools like `mklink` executed from `cmd.exe` or `powershell.exe`. This technique can be used as part of a broader attack to escalate privileges and move laterally within a network, and matters because it provides a way to steal domain credentials without triggering normal access controls.

## Attack Chain

1. An attacker gains initial access to a Windows system, possibly through phishing or exploiting a vulnerability.
2. The attacker elevates privileges to an administrator level, if necessary, to create shadow copies and symbolic links.
3. The attacker uses `vssadmin.exe` or similar tools to create a volume shadow copy of the system drive.
4. The attacker executes `cmd.exe` or `powershell.exe` to create a symbolic link to a directory within the shadow copy using `mklink`. For example, `mklink /D C:\shadow_link \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS`.
5. The attacker accesses the linked directory, which contains the shadow copy of the `ntds.dit` file and the `SYSTEM` registry hive.
6. The attacker copies the `ntds.dit` file and the `SYSTEM` registry hive to a location accessible for offline credential extraction.
7. The attacker uses tools like `secretsdump.py` or `ntdsutil.exe` on a separate system to extract password hashes from the copied `ntds.dit` file and `SYSTEM` registry hive.
8. The attacker uses the extracted credentials to move laterally within the network or compromise domain accounts.

## Impact

Successful exploitation can lead to the compromise of domain credentials, allowing attackers to move laterally within the network, access sensitive data, and potentially disrupt critical services. The impact is particularly severe in Active Directory environments, where stealing the `ntds.dit` file can compromise the entire domain. The number of potential victims depends on the scope of the attacker's access and the size of the targeted network.

## Recommendation

*   Enable and monitor Windows Object Access auditing, specifically Event ID 4656 for file system and handle manipulation events, to detect the creation of symbolic links (references the rule setup and description).
*   Deploy the Sigma rule "Symbolic Link to Shadow Copy Created" to your SIEM to detect the execution of `mklink` with shadow copy paths from `cmd.exe` or `powershell.exe` (references the provided rule).
*   Implement restrictions on the use of `mklink` to prevent non-administrative users from creating symbolic links (references the rule remediation steps).
*   Monitor for the creation of shadow copies using `vssadmin.exe` or other volume shadow copy tools, and investigate any unusual activity (references the attack chain).
*   Investigate any access to `ntds.dit` or copies of the `SYSTEM` registry hive using the investigation steps from the provided rule.
