---
title: Creation of New DMSA Service Account Potentially Exploiting BadSuccessor Vulnerability
slug: 2024-01-08-bad-successor-dmsa
description: The creation of a new Delegated Managed Service Account (DMSA) within specific Organizational Units (OUs) using the New-ADServiceAccount cmdlet is indicative of potential BadSuccessor privilege escalation attempts in Windows Server 2025 Active Directory environments.
date: "2024-01-08T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - active-directory
  - bad-successor
  - dmsa
vendors:
  - Microsoft
products:
  - Windows Server
  - Active Directory
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://www.akamai.com/blog/security-research/abusing-bad-successor-for-privilege-escalation-in-active-directory
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_create_new_dmsasvc_account.yml
rules:
  - title: Suspicious DMSA Creation via PowerShell
    description: Detects the creation of a new dMSASvc account using PowerShell with specific parameters indicative of BadSuccessor exploitation.
    platform: sigma
    severity: medium
    tactics:
      - privilege-escalation
    techniques:
      - T1078.002
    data_sources:
      - process_creation
      - windows
  - title: PowerShell Creating DMSA in Specific OU
    description: Detects the creation of a dMSASvc account using the New-ADServiceAccount cmdlet in certain OUs.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
      - initial-access
      - persistence
      - privilege-escalation
    techniques:
      - T1078.002
      - T1098
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The observed activity involves the suspicious creation of a Delegated Managed Service Account (dMSASvc) using the `New-ADServiceAccount` cmdlet within specific, targeted Organizational Units (OUs) in Windows Server 2025 Active Directory environments. This pattern is strongly associated with attempts to exploit the BadSuccessor vulnerability, a privilege escalation technique. The creation of a DMSA account in a specific OU, especially by a user without legitimate administrative privileges, raises significant concerns. This activity, first highlighted in late 2025, signifies an attacker attempting to gain elevated permissions within the Active Directory domain by abusing the delegation capabilities of DMSA accounts. Defenders should closely monitor for this behavior.

## Attack Chain

1.  Initial access to a system within the target domain is achieved, potentially through compromised credentials or exploiting a separate vulnerability.
2.  The attacker leverages PowerShell (powershell.exe or pwsh.exe) to execute commands.
3.  The `New-ADServiceAccount` cmdlet is invoked with the `-CreateDelegatedServiceAccount` parameter.
4.  The `-Path` parameter specifies a target Organizational Unit (OU) within the Active Directory. The specific OU is often chosen based on its existing permissions and delegation configurations.
5.  The command attempts to create a new dMSASvc account within the specified OU.
6.  If successful, the attacker gains control over the newly created dMSASvc account.
7.  The attacker misuses the delegation rights associated with the dMSASvc account to impersonate other users or services.
8.  The attacker escalates privileges and achieves lateral movement within the Active Directory environment, potentially gaining domain administrator access.

## Impact

Successful exploitation of the BadSuccessor vulnerability can lead to complete domain compromise. Attackers can gain control of sensitive accounts, access confidential data, and disrupt critical business operations. The Akamai report highlights the potential for widespread damage, and the focus on Windows Server 2025 indicates a modern attack targeting recent infrastructure.

## Recommendation

*   Deploy the Sigma rule "New DMSA Service Account Created in Specific OUs" to your SIEM to detect suspicious DMSA creation activity and tune for your environment.
*   Monitor process creation logs for PowerShell execution involving the `New-ADServiceAccount` cmdlet and the `-CreateDelegatedServiceAccount` parameter.
*   Review and restrict Active Directory permissions to prevent unauthorized DMSA account creation.
*   Investigate and remediate any identified instances of unauthorized DMSA account creation.
