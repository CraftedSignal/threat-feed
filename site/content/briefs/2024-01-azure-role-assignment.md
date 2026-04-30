---
title: Azure AD Privileged Role Assignment
slug: 2024-01-azure-role-assignment
description: Detection of a user being added to a privileged role in Azure AD, potentially indicating privilege escalation or persistence by an attacker.
date: "2024-01-02T15:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - privileged-access
  - role-assignment
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-identity-management#azure-ad-roles-assignment
rules:
  - title: Azure AD User Added to Privileged Role (Permanent)
    description: Detects when a user is permanently added to a privileged role in Azure AD.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1078.004
    data_sources:
      - azure
      - auditlogs
  - title: Azure AD User Added to Privileged Role (Eligible)
    description: Detects when a user is made eligible for a privileged role in Azure AD.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1078.004
    data_sources:
      - azure
      - auditlogs
rules_count: 2
---

This alert focuses on the addition of users to privileged roles within Azure Active Directory (Azure AD). An attacker who gains initial access to an account may attempt to escalate privileges to gain broader control over the Azure environment. This can be achieved by adding the compromised account or a new attacker-controlled account to a highly privileged role. This activity often occurs after an initial compromise and is a critical step in establishing persistence and expanding access within the target environment. Successful role assignment allows the attacker to perform actions normally restricted to administrators, potentially leading to data exfiltration, service disruption, or further lateral movement. This activity is visible in the Azure Audit Logs.

## Attack Chain

1.  An attacker gains initial access to an Azure AD account through credential phishing or password spraying (T1078.004).
2.  The attacker identifies potential target roles with high privileges within the Azure AD environment.
3.  The attacker attempts to add the compromised account, or a new account under their control, to one of these privileged roles.
4.  The attacker executes an "Add eligible member" action, either permanent or eligible, within Azure AD, which is logged in the audit logs.
5.  Azure AD processes the request and, if successful, grants the new role assignment to the target account.
6.  The attacker uses the newly acquired privileges to access sensitive resources, modify configurations, or deploy malicious applications.
7.  The attacker establishes persistence by creating new administrative accounts or modifying existing configurations to maintain access even if the initial compromised account is remediated.
8.  The attacker performs data exfiltration or causes disruption to the Azure environment based on their objectives.

## Impact

Successful addition of a user to a privileged role can grant the attacker complete control over the Azure AD environment. This may allow them to access sensitive data, disrupt critical services, and deploy malicious applications. The impact can range from data breaches and financial loss to complete compromise of the organization's cloud infrastructure. The scope depends on the role assigned, but global administrator roles can cause catastrophic damage.

## Recommendation

*   Deploy the Sigma rule "User Added To Privilege Role" to your SIEM to detect suspicious role assignments in Azure AD Audit Logs.
*   Review Azure AD audit logs for any "Add eligible member" events (permanent or eligible) to identify potentially malicious role assignments.
*   Implement multi-factor authentication (MFA) for all users, especially those with administrative privileges, to mitigate the risk of initial access compromise (T1110).
*   Enforce the principle of least privilege to limit the scope of access for each user and role (T1068).
*   Regularly audit and review user role assignments to identify and remove unnecessary privileges.
