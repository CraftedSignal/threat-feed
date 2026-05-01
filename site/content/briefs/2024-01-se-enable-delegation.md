---
title: SeEnableDelegationPrivilege Assignment Detection
slug: 2024-01-se-enable-delegation
description: Detection of the assignment of the SeEnableDelegationPrivilege user right to a principal can indicate potential Active Directory compromise and privilege elevation by attackers.
date: "2024-01-03T17:23:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - persistence
  - windows
  - active-directory
vendors:
  - Microsoft
products:
  - Active Directory
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1558
    technique_name: Steal or Forge Kerberos Tickets
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1558
    technique_name: Steal or Forge Kerberos Tickets
references:
  - https://blog.harmj0y.net/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/
  - https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_alert_active_directory_user_control.yml
  - https://twitter.com/_nwodtuhs/status/1454049485080907776
  - https://www.thehacker.recipes/ad/movement/kerberos/delegations
  - https://github.com/atc-project/atomic-threat-coverage/blob/master/Atomic_Threat_Coverage/Logging_Policies/LP_0105_windows_audit_authorization_policy_change.md
rules:
  - title: SeEnableDelegationPrivilege Assigned to User
    description: Detects the assignment of the SeEnableDelegationPrivilege user right.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - persistence
    techniques:
      - T1558.003
    data_sources:
      - security
      - windows
  - title: SeEnableDelegationPrivilege Assigned via PowerShell
    description: Detects the assignment of SeEnableDelegationPrivilege via PowerShell.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - persistence
    techniques:
      - T1059.001
      - T1558.003
    data_sources:
      - process_creation
      - windows
  - title: SeEnableDelegationPrivilege Assigned via ntrights.exe
    description: Detects the assignment of SeEnableDelegationPrivilege via ntrights.exe.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - persistence
    techniques:
      - T1053.005
      - T1558.003
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

The SeEnableDelegationPrivilege user right, when assigned to a security principal, allows that principal to be trusted for delegation within Active Directory. Attackers can abuse this right to compromise accounts and elevate privileges by impersonating other users or services. This technique can be used for lateral movement, persistence, and ultimately, domain dominance. Defenders should monitor for the assignment of this privilege, especially to accounts that should not have it. The targeted behavior is logged as event ID 4704 in Windows Security logs. This activity is critical to monitor as it represents a powerful tool for attackers to move laterally and maintain persistence within a compromised environment.

## Attack Chain

1.  An attacker gains initial access to a compromised account with sufficient privileges to modify user rights.
2.  The attacker assigns the SeEnableDelegationPrivilege to a target account using tools like `ntrights.exe` or PowerShell cmdlets.
3.  Windows Security Event 4704 is generated, logging the privilege assignment.
4.  The attacker modifies the target account's attributes, such as `userAccountControl` or `msDS-AllowedToDelegateTo`, to enable delegation.
5.  The attacker leverages Kerberos delegation to impersonate other users or services.
6.  Using the impersonated credentials, the attacker accesses sensitive resources or performs privileged actions.
7.  The attacker moves laterally within the network, compromising additional systems and accounts.
8.  The attacker achieves their final objective, such as data exfiltration or domain dominance.

## Impact

Successful exploitation allows attackers to compromise Active Directory accounts and elevate privileges, potentially leading to full control over the domain. The impact includes unauthorized access to sensitive data, lateral movement to critical systems, and the potential for long-term persistence. Depending on the compromised accounts, the entire organization can be at risk.

## Recommendation

*   Enable "Audit Authorization Policy Change" to generate Windows Security Event ID 4704 (Setup instructions: https://ela.st/audit-authorization-policy-change).
*   Deploy the Sigma rule "Sensitive Privilege SeEnableDelegationPrivilege assigned to a Principal" to your SIEM to detect the assignment of this privilege.
*   Investigate any instances where SeEnableDelegationPrivilege is assigned, focusing on the targeted account and the source of the change.
*   Monitor for modifications to delegation-related attributes on user and computer objects.
