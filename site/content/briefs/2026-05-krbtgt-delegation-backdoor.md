---
title: KRBTGT Delegation Backdoor via msDS-AllowedToDelegateTo Modification
slug: 2026-05-krbtgt-delegation-backdoor
description: Attackers can modify the msDS-AllowedToDelegateTo attribute to KRBTGT, enabling persistent domain access by requesting Kerberos tickets for the KRBTGT service.
date: "2026-05-12T18:39:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - active-directory
  - windows
vendors:
  - Elastic
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1558
    technique_name: Steal or Forge Kerberos Tickets
references:
  - https://skyblue.team/posts/delegate-krbtgt
  - https://github.com/atc-project/atomic-threat-coverage/blob/master/Atomic_Threat_Coverage/Logging_Policies/LP_0026_windows_audit_user_account_management.md
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_msds_alloweddelegateto_krbtgt.toml
rules:
  - title: Detect KRBTGT Delegation Modification via Event ID 4738
    description: Detects modification of the msDS-AllowedToDelegateTo attribute to KRBTGT via Windows Event ID 4738.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1558.003
    data_sources:
      - registry_set
      - windows
  - title: KRBTGT Delegation Backdoor via AllowedToDelegateTo
    description: Detects modification of user accounts to delegate to KRBTGT.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1558.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers can establish a persistent backdoor in Active Directory by modifying the `msDS-AllowedToDelegateTo` attribute of an account to include the KRBTGT service. This allows them to request Kerberos tickets for the KRBTGT account, effectively granting them domain administrator privileges. This technique bypasses normal authentication mechanisms and can persist even after password resets. The modification is typically performed through Active Directory management tools or PowerShell scripts. Successful exploitation allows attackers to move laterally, access sensitive data, and compromise the entire domain. This activity can be detected via Windows Security Event Logs, specifically event ID 4738.

## Attack Chain

1.  Compromise an account with sufficient privileges to modify Active Directory attributes.
2.  Identify the target account to modify (e.g., a service account or a user account).
3.  Use Active Directory management tools or PowerShell to modify the `msDS-AllowedToDelegateTo` attribute of the target account.
4.  Add the KRBTGT service principal name (SPN) to the `msDS-AllowedToDelegateTo` attribute (e.g., `krbtgt/DOMAIN.LOCAL`).
5.  The attacker leverages the compromised account to request Kerberos tickets for the KRBTGT service.
6.  Using the obtained Kerberos ticket, the attacker authenticates to other systems in the domain as if they were the KRBTGT account.
7.  The attacker gains control over domain resources and data.
8.  The attacker establishes persistence by maintaining the backdoor through the compromised account.

## Impact

Successful exploitation of this technique grants attackers persistent domain administrator privileges. This allows them to access sensitive data, compromise other systems in the domain, and potentially disrupt business operations. This technique bypasses normal authentication mechanisms and can persist even after password resets. The impact can range from data breaches and financial loss to complete disruption of critical services.

## Recommendation

*   Enable auditing for User Account Management to generate the necessary event logs (Event ID 4738). Refer to the setup instructions in the rule documentation.
*   Monitor Windows Security Event Logs for Event ID 4738 with `AllowedToDelegateTo` containing `krbtgt`, using the "KRBTGT Delegation Backdoor" rule.
*   Investigate any modifications to the `msDS-AllowedToDelegateTo` attribute of accounts, particularly those involving KRBTGT, as described in the Triage and Analysis section of the rule documentation.
*   Implement strict access controls and monitoring for accounts with privileges to modify Active Directory attributes to prevent unauthorized changes.
*   Regularly review and audit delegation settings to identify and remove any unauthorized delegations.
