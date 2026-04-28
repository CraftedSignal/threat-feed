---
title: User Added to Group with Conditional Access Policy Modification Access
slug: 2024-01-azure-group-add
description: An attacker adds a user to a privileged Azure Active Directory group with permissions to modify Conditional Access policies, potentially leading to privilege escalation, credential access, persistence, and defense impairment.
date: "2024-01-03T18:22:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - attack.privilege-escalation
  - attack.credential-access
  - attack.persistence
  - attack.defense-impairment
  - attack.t1548
  - attack.t1556
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://learn.microsoft.com/en-us/entra/architecture/security-operations-infrastructure#conditional-access
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_group_user_addition_ca_modification.yml
rules:
  - title: User Added To Group With CA Policy Modification Access
    description: Detects when a user is added to a group that has Conditional Access policy modification access.
    platform: sigma
    severity: medium
    tactics:
      - privilege-escalation
    techniques:
      - T1548
    data_sources:
      - azure
      - auditlogs
  - title: Conditional Access Policy Modified
    description: Detects modifications to Conditional Access policies in Azure AD.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    techniques:
      - T1556
    data_sources:
      - azure
      - auditlogs
  - title: Azure AD Group Membership Changes
    description: Detects changes to group memberships in Azure AD, which can indicate potential privilege escalation.
    platform: sigma
    severity: informational
    tactics:
      - privilege-escalation
    techniques:
      - T1548
    data_sources:
      - azure
      - auditlogs
rules_count: 3
---

This activity involves the addition of a user to an Azure Active Directory group that possesses the ability to modify Conditional Access (CA) policies. Conditional Access policies are used to enforce authentication requirements based on various conditions (user, location, device, etc.). If an attacker gains the ability to modify these policies, they can weaken security controls to facilitate privilege escalation, credential access, persistence within the environment, and impair defenses. This type of attack can be initiated by an insider threat or external compromise of an account. The goal is to manipulate CA policies to bypass multi-factor authentication, grant unauthorized access, or maintain persistence.

## Attack Chain

1.  The attacker gains initial access to a user account or service principal with sufficient privileges to manage group memberships in Azure AD. This could be achieved through credential compromise or other initial access vectors.
2.  The attacker identifies a target Azure AD group that has permissions to manage Conditional Access policies. These groups are often used to delegate administrative control over CA policies.
3.  The attacker uses the Azure portal, PowerShell, or the Azure AD Graph API/Microsoft Graph API to add a malicious user account to the target group.
4.  The Azure Audit Logs record the "Add member from group" event, indicating the change in group membership.
5.  The newly added malicious user inherits the group's permissions, which includes the ability to view, create, modify, and delete Conditional Access policies.
6.  The attacker modifies existing CA policies to weaken security controls. For example, they might exclude themselves from MFA requirements or grant access to sensitive resources without proper authorization.
7.  The attacker leverages their modified CA policies to gain unauthorized access to sensitive data or resources.
8.  The attacker establishes persistence by creating new CA policies that ensure their continued access, even if their initial access is revoked.

## Impact

Successful exploitation of this attack chain can lead to significant compromise of an organization's Azure environment. Attackers can bypass MFA, gain access to sensitive resources, establish persistent access, and impair security defenses. The extent of the damage depends on the permissions associated with the compromised group and the scope of the modified Conditional Access policies. This can lead to data breaches, financial loss, and reputational damage.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect additions of users to groups with CA policy modification access and tune for your environment.
*   Regularly review and audit Azure AD group memberships, especially for groups with administrative privileges (as detected by the Sigma rule).
*   Implement multi-factor authentication for all users, especially those with administrative privileges.
*   Enforce the principle of least privilege when assigning permissions to Azure AD groups.
*   Monitor Azure AD audit logs for suspicious activity related to group membership changes and Conditional Access policy modifications.
