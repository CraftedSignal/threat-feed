---
title: Suspicious dMSA Service Account Creation Attempting BadSuccessor Abuse
slug: 2024-01-badsuccessor-dmsa
description: The creation of a delegated managed service account (dMSA) in specific Active Directory organizational units (OUs) via PowerShell, especially when the initiating user lacks proper permissions, indicates a potential attempt to exploit the BadSuccessor privilege escalation vulnerability in Windows Server 2025 environments.
date: "2024-01-02T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - attack.privilege-escalation
  - attack.initial-access
  - attack.defense-evasion
  - attack.persistence
  - attack.t1078.002
  - attack.t1098
vendors:
  - Microsoft
products:
  - Active Directory
  - Windows Server 2025
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0006
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://www.akamai.com/blog/security-research/abusing-bad-successor-for-privilege-escalation-in-active-directory
rules:
  - title: DMSA Service Account Creation in Sensitive OUs - PowerShell
    description: Detects the creation of a dMSA service account using the New-ADServiceAccount cmdlet in certain OUs, which can indicate BadSuccessor exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
      - privilege-escalation
    techniques:
      - T1078.002
    data_sources:
      - ps_script
      - windows
  - title: PowerShell -ADServiceAccount Cmdlets
    description: Detects the use of any -ADServiceAccount cmdlets in powershell
    platform: sigma
    severity: low
    tactics:
      - initial-access
      - privilege-escalation
    techniques:
      - T1078.002
    data_sources:
      - ps_script
      - windows
rules_count: 2
---

This activity focuses on the suspicious creation of delegated managed service accounts (dMSAs) within specific organizational units (OUs) in Active Directory using PowerShell. This technique is associated with attempts to exploit the BadSuccessor privilege escalation vulnerability in Windows Server 2025. The exploitation involves using the `New-ADServiceAccount` cmdlet with parameters like `-CreateDelegatedServiceAccount` and `-path` to create a dMSA in a targeted OU. The risk is amplified when the user initiating the dMSA creation lacks legitimate administrative privileges, pointing towards unauthorized privilege escalation. Defenders should be aware of unusual dMSA creation activities, especially in environments running Windows Server 2025, and monitor for users attempting to manipulate Active Directory objects without proper authorization. This behavior is indicative of lateral movement and persistence attempts post initial compromise.

## Attack Chain

1.  Initial Access: An attacker gains initial access to a compromised user account, possibly through phishing or credential theft (T1078.002).
2.  Reconnaissance: The attacker performs reconnaissance to identify vulnerable Active Directory environments and potential target OUs.
3.  Privilege Escalation Preparation: The attacker attempts to create a dMSA service account within a specific OU using PowerShell.
4.  dMSA Creation: The attacker executes the `New-ADServiceAccount` cmdlet with parameters such as `-CreateDelegatedServiceAccount` and specifying a `-path` to a targeted OU.
5.  BadSuccessor Exploitation: The attacker leverages the BadSuccessor vulnerability to manipulate the newly created dMSA, granting themselves elevated privileges.
6.  Persistence: The attacker uses the elevated privileges to establish persistence within the Active Directory environment (T1098).
7.  Lateral Movement: With elevated privileges, the attacker moves laterally to other systems within the domain.
8.  Objective: The ultimate objective could be data exfiltration, deployment of ransomware, or further compromise of critical systems.

## Impact

Successful exploitation of the BadSuccessor vulnerability can lead to a complete compromise of the Active Directory domain. An attacker could gain control over sensitive accounts, critical systems, and sensitive data. The impact includes data breaches, service disruptions, and potential financial losses. The risk is especially high in environments running unpatched Windows Server 2025 instances.

## Recommendation

*   Deploy the Sigma rule `DMSA Service Account Created in Specific OUs - PowerShell` to your SIEM to detect suspicious dMSA creation attempts (logsource: ps_script).
*   Monitor PowerShell logs (category: ps_script, product: windows) for the use of `New-ADServiceAccount` with `-CreateDelegatedServiceAccount` and `-path` parameters.
*   Implement strict Active Directory permissioning and regularly audit user privileges to prevent unauthorized dMSA creation.
*   Patch Windows Server 2025 environments to mitigate the BadSuccessor vulnerability referenced in the Akamai blog post (references).
