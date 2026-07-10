---
title: 'Entra ID: Global Administrator Role Assigned to PIM User'
slug: 2024-01-entra-id-pim-global-admin-role-addition
description: An adversary may add an account to the Global Administrator role within Azure AD Privileged Identity Management (PIM) to establish persistence and gain privileged access.
date: "2024-01-04T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - entra_id
  - persistence
  - privilege_escalation
vendors:
  - Microsoft
products:
  - Azure Active Directory
  - Privileged Identity Management
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/directory-assign-admin-roles
rules:
  - title: Entra ID Global Administrator Role Assigned (PIM User)
    description: Detects the addition of a user to the Global Administrator role within Privileged Identity Management (PIM) in Azure AD.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - auditlogs
      - azure
  - title: Entra ID PIM Role Activation
    description: Detects activation of an eligible role in Entra ID PIM
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    data_sources:
      - auditlogs
      - azure
rules_count: 2
---

This alert identifies when a user is added to the Global Administrator role in Azure Active Directory (Azure AD) through Privileged Identity Management (PIM). Azure AD Global Administrator roles grant extensive permissions allowing modification of any administrative setting within the Azure AD organization. Privileged Identity Management (PIM) is used to manage, control, and monitor access to important resources. An adversary might add themselves, or another account they control, to the Global Administrator role via PIM to gain persistent, highly privileged access to the Azure environment. This could lead to data exfiltration, service disruption, or further lateral movement within the cloud environment. The rule specifically looks for "Add eligible member to role in PIM completed (permanent)" or "Add member to role in PIM completed (timebound)" events.

## Attack Chain

1.  The attacker compromises an existing user account with sufficient privileges to manage roles in Azure AD PIM, possibly via phishing (T1566).
2.  The attacker authenticates to the Azure portal using the compromised account.
3.  The attacker navigates to the Privileged Identity Management (PIM) service within Azure AD.
4.  The attacker initiates a request to add a target user account (potentially themselves or an account they control) to the Global Administrator role.
5.  The attacker completes the process of assigning the Global Administrator role to the target user, either permanently or with a time-bound assignment, using the compromised account's permissions.
6.  Azure AD logs an audit event indicating the successful addition of the user to the Global Administrator role in PIM. The `azure.auditlogs.operation_name` will contain "Add eligible member to role in PIM completed (permanent)" or "Add member to role in PIM completed (timebound)".
7.  The attacker leverages the newly assigned Global Administrator privileges to perform malicious actions such as modifying security settings, accessing sensitive data, or deploying malicious applications.
8.  The attacker maintains persistence by ensuring the Global Administrator role assignment remains active, allowing continued access to the environment.

## Impact

Successful exploitation allows the attacker to gain full control over the Azure AD environment. A Global Administrator can read and modify any administrative setting. This includes the ability to create new users, reset passwords, modify security policies, access all data stored in the cloud environment, and disrupt critical services. The impact could range from data breaches and financial losses to complete compromise of the organization's cloud infrastructure.

## Recommendation

*   Deploy the Sigma rule "Entra ID Global Administrator Role Assigned (PIM User)" to your SIEM and tune for your environment to detect unauthorized role assignments (rule).
*   Review Azure AD audit logs for any unexpected additions of users to highly privileged roles, especially the Global Administrator role (logsource).
*   Implement multi-factor authentication (MFA) for all user accounts, especially those with administrative privileges, to reduce the risk of account compromise (T1566).
*   Enforce the principle of least privilege by granting users only the minimum necessary permissions to perform their job functions.
*   Regularly review and audit role assignments in Azure AD to identify and remove any unnecessary or excessive privileges.
*   Implement alerts for any changes to PIM settings to detect potential tampering with privileged access management controls (logsource).
