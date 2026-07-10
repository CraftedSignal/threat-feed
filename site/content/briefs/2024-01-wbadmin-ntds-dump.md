---
title: NTDS Dump via Wbadmin Execution
slug: 2024-01-wbadmin-ntds-dump
description: Adversaries with Backup Operator privileges can abuse the legitimate Windows utility `wbadmin.exe` to dump the NTDS.dit file, enabling credential access and domain compromise.
date: "2024-01-24T18:53:00Z"
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
  - https://medium.com/r3d-buck3t/windows-privesc-with-sebackupprivilege-65d2cd1eb960
  - https://attack.mitre.org/techniques/T1003/
  - https://attack.mitre.org/techniques/T1003/002/
  - https://attack.mitre.org/techniques/T1003/003/
  - https://attack.mitre.org/techniques/T1006/
  - https://attack.mitre.org/tactics/TA0006/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: NTDS Dump via Wbadmin
    description: Detects the execution of wbadmin with arguments used to dump the NTDS.dit file.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1003.003
      - T1006
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Wbadmin Execution from Non-Standard Path
    description: Detects wbadmin.exe execution from a non-standard path, which might indicate malicious activity.
    platform: sigma
    severity: low
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1003.003
      - T1006
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This rule detects the execution of `wbadmin.exe` with arguments indicative of an attempt to access and dump the NTDS.dit file on a domain controller. Attackers often leverage this technique after gaining sufficient privileges, such as membership in the Backup Operators group. By abusing `wbadmin.exe`, adversaries bypass traditional credential access controls. The NTDS.dit file contains sensitive credential information, and successful exfiltration can lead to complete domain compromise. Defenders should monitor `wbadmin.exe` execution, especially when combined with specific arguments related to NTDS.dit access, to identify potential credential dumping activities. The technique leverages legitimate system administration tools for malicious purposes, making it harder to detect without specific rules. The scope of this attack affects Windows domain controllers.

## Attack Chain

1. An attacker gains initial access to a Windows system, possibly through phishing or exploiting a vulnerability.
2. The attacker escalates privileges to obtain Backup Operators group membership or equivalent privileges necessary to run `wbadmin.exe`.
3. The attacker executes `wbadmin.exe` with the `recovery` parameter and a command line that includes a reference to the `ntds.dit` file.
4. `wbadmin.exe` initiates a backup process that includes the NTDS.dit file, potentially storing it in a temporary location.
5. The attacker retrieves the backed-up `ntds.dit` file from the temporary location.
6. The attacker uses tools like `ntdsutil.exe` or `secretsdump.py` to extract password hashes from the `ntds.dit` file.
7. The attacker cracks the extracted password hashes or uses them in pass-the-hash attacks.
8. Using the compromised credentials, the attacker moves laterally within the network to access sensitive resources and data, or achieves complete domain dominance.

## Impact

A successful NTDS.dit dump allows attackers to extract password hashes for all domain users and service accounts. This grants them the ability to impersonate legitimate users, access sensitive data, and move laterally throughout the network. The impact can range from data breaches and financial loss to complete disruption of business operations. The risk is especially high for organizations that do not implement strong password policies or multi-factor authentication, as cracked passwords provide immediate access. Compromised domain administrator accounts can lead to complete domain takeover, requiring extensive recovery efforts.

## Recommendation

*   Deploy the Sigma rule `NTDS Dump via Wbadmin` to your SIEM and tune for your environment to detect the malicious use of `wbadmin.exe` (rule).
*   Review user accounts with Backup Operators privileges and remove any unauthorized accounts (overview).
*   Monitor process creation events for `wbadmin.exe` execution with command-line arguments related to `ntds.dit` (rule).
*   Enable Sysmon process-creation logging to activate the rule above (rule).
*   Implement strict access controls on domain controllers to prevent unauthorized access to the NTDS.dit file (overview).
*   Implement enhanced monitoring and logging for wbadmin.exe usage across all domain controllers to detect future unauthorized access attempts (overview).
