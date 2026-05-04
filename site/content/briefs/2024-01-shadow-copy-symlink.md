---
title: Symbolic Link Creation to Shadow Copies for Credential Access
slug: 2024-01-shadow-copy-symlink
description: Adversaries may create symbolic links to shadow copies to access sensitive files such as ntds.dit and browser credentials, enabling credential dumping using cmd.exe or powershell.exe.
date: "2024-01-03T18:15:00Z"
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
  - Elastic
  - CrowdStrike
  - SentinelOne
products:
  - Microsoft Defender XDR
  - Elastic Defend
  - CrowdStrike
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
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
  - title: Symbolic Link to Shadow Copy Created via Cmd
    description: Detects the creation of symbolic links to shadow copies using the mklink command via cmd.exe, often used to access sensitive files for credential dumping.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1003
      - T1006
    data_sources:
      - process_creation
      - windows
  - title: Symbolic Link to Shadow Copy Created via PowerShell
    description: Detects the creation of symbolic links to shadow copies using PowerShell, often used to access sensitive files for credential dumping.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1003
      - T1006
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This rule identifies the creation of symbolic links to shadow copies on Windows systems. Attackers use this technique to gain access to sensitive files stored within shadow copies, including the ntds.dit file (containing password hashes), system boot keys, and browser offline credentials. This approach allows them to bypass normal file access controls and extract credentials for lateral movement or privilege escalation. The detection rule is designed to ingest data from various sources, including Elastic Defend, CrowdStrike, Microsoft Defender XDR, SentinelOne Cloud Funnel, Sysmon, and Windows Security Event Logs, providing broad coverage across different endpoint security solutions. The activity is typically initiated by command-line tools like cmd.exe or powershell.exe, making detection through process monitoring feasible. This technique is particularly relevant as it targets credential dumping, a critical stage in many attack campaigns.

## Attack Chain

1.  An attacker gains initial access to a Windows system, possibly through phishing or exploitation of a vulnerability.
2.  The attacker elevates privileges to gain administrative rights, which are required to create shadow copies and symbolic links.
3.  The attacker creates a volume shadow copy using `vssadmin.exe` or similar tools.
4.  The attacker uses `mklink` command or PowerShell `New-Item -ItemType SymbolicLink` to create a symbolic link to the shadow copy path.
5.  The symbolic link points to a directory within the shadow copy containing sensitive files like `ntds.dit` or browser credential stores.
6.  The attacker copies the targeted sensitive files (e.g., `ntds.dit`) from the shadow copy using the symbolic link.
7.  The attacker removes the shadow copy to cover their tracks, although the symbolic link creation remains as evidence.
8.  The attacker extracts credentials from the copied `ntds.dit` file offline for use in lateral movement or further attacks.

## Impact

Successful exploitation allows attackers to gain unauthorized access to sensitive credentials stored on the compromised system. This can lead to lateral movement within the network, privilege escalation, and ultimately, the compromise of critical assets. If the `ntds.dit` file is accessed, the entire Active Directory domain could be at risk, potentially affecting thousands of users and systems. This type of attack is particularly damaging as it allows attackers to operate undetected for extended periods while they harvest credentials.

## Recommendation

*   Deploy the provided Sigma rule "Symbolic Link to Shadow Copy Created via Cmd" to detect the creation of symbolic links to shadow copies via `cmd.exe` (rules).
*   Deploy the provided Sigma rule "Symbolic Link to Shadow Copy Created via PowerShell" to detect the creation of symbolic links to shadow copies via `powershell.exe` (rules).
*   Enable Sysmon Event ID 1 (Process Creation) logging to provide necessary data for the Sigma rules to function correctly (setup).
*   Review the "Investigating Symbolic Link to Shadow Copy Created" section in the rule's notes for triage and analysis steps when the rule triggers.
*   Monitor for the usage of `mklink` command with the `HarddiskVolumeShadowCopy` argument in process command lines.
