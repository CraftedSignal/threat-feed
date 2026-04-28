---
title: Detection of Privileged Identity Management (PIM) Settings Modifications
slug: 2024-01-03-azure-pim-settings-change
description: Detects unauthorized or malicious modifications to Privileged Identity Management (PIM) settings within Azure environments, potentially leading to privilege escalation, persistence, and stealthy access by attackers.
date: "2024-01-03T14:30:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - azure
  - pim
  - privilege-escalation
  - persistence
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
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0006
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-identity-management#azure-ad-roles-assignment
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_pim_change_settings.yml
rules:
  - title: Detect PIM Role Setting Changes via Audit Logs
    description: Detects modifications to PIM role settings based on Azure Audit Logs.
    platform: sigma
    severity: high
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078.004
    data_sources:
      - azure
      - auditlogs
  - title: Detect PIM Role Assignment Changes via Audit Logs
    description: Detects modifications to PIM role assignments based on Azure Audit Logs.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078.004
    data_sources:
      - azure
      - auditlogs
rules_count: 2
---

Privileged Identity Management (PIM) is a critical component of Azure Active Directory, enabling organizations to manage, control, and monitor access to important resources. Attackers often target PIM configurations to escalate privileges, establish persistence, or move laterally within a compromised environment. This activity focuses on detecting changes to PIM role settings, which could indicate malicious activity aimed at weakening security controls. Defenders must monitor these changes to prevent unauthorized access and maintain the integrity of their Azure environment. This includes understanding who is making these changes, the scope of the modifications, and whether the changes align with established security policies.

## Attack Chain

1. **Initial Compromise:** The attacker gains initial access to an account with sufficient privileges to view PIM settings.
2. **Discovery:** The attacker enumerates existing PIM role settings within the Azure Active Directory environment.
3. **Modification:** The attacker modifies existing PIM role settings, such as extending the maximum activation time or removing approval requirements, using the Azure portal, PowerShell, or the Azure CLI.
4. **Privilege Escalation:** By modifying PIM settings, the attacker escalates their privileges, granting themselves elevated access to sensitive resources or administrative functions.
5. **Persistence:** The attacker establishes persistence by creating new or modifying existing role assignments to maintain access even if their initial account is compromised.
6. **Lateral Movement:** With escalated privileges, the attacker moves laterally to access other resources or accounts within the Azure environment.
7. **Data Exfiltration/Impact:** The attacker leverages their escalated privileges to exfiltrate sensitive data, disrupt services, or cause other damage.

## Impact

Successful modification of PIM settings can have severe consequences, including unauthorized access to sensitive data, disruption of critical services, and privilege escalation leading to complete compromise of the Azure environment. A single compromised PIM setting can affect multiple users and resources, amplifying the impact of the attack. Early detection of PIM setting modifications can prevent attackers from gaining a foothold and causing significant damage.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect changes to PIM settings based on the `properties.message` field within Azure audit logs.
*   Regularly review Azure audit logs for events related to PIM configuration changes, paying close attention to the user accounts making the changes and the scope of the modifications.
*   Implement multi-factor authentication (MFA) for all accounts with privileges to manage PIM settings.
*   Enforce the principle of least privilege by granting users only the minimum permissions required to perform their job functions.
*   Establish a baseline of normal PIM settings and alert on any deviations from this baseline.
*   Investigate any alerts triggered by the Sigma rule by correlating them with other security events and user activity.
*   Implement automated responses to detected PIM setting modifications, such as disabling the affected user account or reverting the changes.
