---
title: Azure PIM - Role Assignment Outside of Privileged Identity Management
slug: 2024-01-azure-pim-role-assigned-outside
description: Detection of privilege role assignments outside of Azure Privileged Identity Management (PIM) can indicate potential attacker activity related to initial access, stealth, persistence, or privilege escalation within the Azure environment.
date: "2024-01-02T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - azure
  - pim
  - role-assignment
  - attack.initial-access
  - attack.stealth
  - attack.t1078
  - attack.persistence
  - attack.privilege-escalation
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts#roles-are-being-assigned-outside-of-privileged-identity-management
rules:
  - title: Azure PIM - Roles Assigned Outside Privileged Identity Management
    description: Detects when a privileged role assignment has taken place outside of PIM, which may indicate an attack.
    platform: sigma
    severity: high
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078
    data_sources:
      - azure
      - pim
  - title: Azure PIM - Potential Brute Force of PIM Activation
    description: Detects multiple failed attempts to activate a role via PIM, potentially indicating a brute-force attack.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
      - privilege-escalation
    data_sources:
      - azure
      - pim
rules_count: 2
---

The unauthorized assignment of privileged roles outside of Azure Privileged Identity Management (PIM) represents a significant security risk. Attackers may attempt to bypass PIM controls to gain persistent access, escalate privileges, or move laterally within the Azure environment. Detecting these anomalous role assignments is crucial for identifying potentially compromised accounts or malicious insiders. This activity is a common tactic used by attackers to establish persistence and maintain control over cloud resources. Monitoring for this behavior can help security teams quickly identify and respond to potential breaches, limiting the impact of successful attacks. This activity can be associated with lateral movement, privilege escalation, and persistence within the cloud environment.

## Attack Chain

1. An attacker gains initial access to a compromised user account or service principal within the Azure environment.
2. The attacker attempts to identify existing privileged roles and permissions.
3. The attacker bypasses PIM to directly assign themselves a privileged role (e.g., Global Administrator, Security Administrator) using Azure CLI, PowerShell, or the Azure portal.
4. The attacker elevates their permissions without triggering PIM alerts or requiring approval.
5. The attacker uses the newly assigned privileged role to access sensitive data, modify configurations, or create new resources.
6. The attacker establishes persistence by creating new accounts or modifying existing ones with elevated privileges.
7. The attacker moves laterally to other Azure resources or subscriptions using their increased access.
8. The attacker achieves their final objective, such as data exfiltration, service disruption, or deployment of malicious code.

## Impact

Compromising privileged roles within Azure can have severe consequences, potentially impacting all resources within the affected Azure Active Directory tenant. Successful attacks can lead to unauthorized data access, service disruption, financial loss, and reputational damage. The scope of the impact depends on the level of privilege gained by the attacker and the sensitivity of the targeted resources. Without proper detection and response, organizations may remain unaware of the breach, allowing attackers to maintain persistent access and continue their malicious activities undetected.

## Recommendation

*   Deploy the provided Sigma rule `Roles Assigned Outside PIM` to your SIEM to detect unauthorized role assignments within your Azure environment.
*   Investigate all instances flagged by the Sigma rule `Roles Assigned Outside PIM` to determine the legitimacy of the role assignment and the identity of the assigner.
*   Implement controls to restrict the ability to assign privileged roles outside of PIM, as described in the Microsoft documentation reference.
*   Review and enforce the principle of least privilege to minimize the potential impact of compromised accounts.
