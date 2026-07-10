---
title: Azure AD Global Administrator Role Assigned
slug: 2024-01-azuread-global-admin-assigned
description: Detection of Azure AD Global Administrator role assignment to a user, potentially leading to privilege escalation and control over Azure resources.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - azuread
  - privilege-escalation
  - persistence
vendors:
  - Microsoft
products:
  - Azure Active Directory
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
  - https://o365blog.com/post/admin/
  - https://adsecurity.org/?p=4277
  - https://www.mandiant.com/resources/detecting-microsoft-365-azure-active-directory-backdoors
  - https://docs.microsoft.com/en-us/azure/active-directory/roles/security-planning
  - https://docs.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin
  - https://attack.mitre.org/techniques/T1098/003/
rules:
  - title: Azure AD Global Administrator Role Assigned
    description: Detects the assignment of the Azure AD Global Administrator role to a user.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - cloudtrail
      - azure
      - o365
  - title: Azure AD Global Administrator Role Assigned via Service Principal
    description: Detects the assignment of the Azure AD Global Administrator role to a user by a Service Principal.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - cloudtrail
      - azure
      - o365
rules_count: 2
---

This analytic detects the assignment of the Azure AD Global Administrator role to a user by monitoring Azure Active Directory AuditLogs for the "Add member to role" operation including the "Global Administrator" role. The Global Administrator role grants extensive access to data, resources, and settings, similar to a Domain Administrator in traditional AD environments. This activity, if malicious, could allow an attacker to establish persistence, escalate privileges, and potentially gain control over Azure resources. The detection leverages Azure Active Directory AuditLogs with the azure:monitor:aad sourcetype and AuditLogs log category. This poses a severe security risk and requires immediate investigation.

## Attack Chain

1.  The attacker gains initial access to an account with sufficient privileges to modify Azure AD roles.
2.  The attacker navigates to the Azure Active Directory admin center or uses PowerShell cmdlets to manage roles.
3.  The attacker selects the "Roles and administrators" option within Azure AD.
4.  The attacker chooses the "Global Administrator" role.
5.  The attacker adds a new member (either an existing user or a newly created account) to the Global Administrator role.
6.  Azure AD AuditLogs record an event with operationName "Add member to role" and a modified property indicating the assignment of the "Global Administrator" role.
7.  The newly assigned Global Administrator account is used to access sensitive data, modify configurations, or create new administrative accounts.
8.  The attacker achieves persistence and control over Azure resources, potentially leading to data exfiltration or service disruption.

## Impact

Successful assignment of the Global Administrator role allows an attacker to establish persistence, escalate privileges, and potentially gain complete control over Azure resources. The attacker could access sensitive data, modify critical configurations, and create new administrative accounts. This can lead to data breaches, service disruptions, and significant financial and reputational damage. The number of affected users and the scope of impact depend on the extent of the attacker's access and activities after gaining the Global Administrator role.

## Recommendation

*   Deploy the provided Sigma rule `Azure AD Global Administrator Role Assigned` to your SIEM and tune for your environment using the data from your `azure:monitor:aad` sourcetype.
*   Investigate any detected assignments of the Global Administrator role immediately, focusing on the source account (`initiatedBy`) and the target user (`user`).
*   Review Azure AD audit logs for other suspicious activities performed by the involved accounts.
*   Implement multi-factor authentication (MFA) for all administrative accounts to reduce the risk of unauthorized access.
*   Follow the principle of least privilege when assigning Azure AD roles, granting only the necessary permissions to users.
*   Regularly review and audit Azure AD role assignments to identify and remove any unnecessary or inappropriate privileges.
