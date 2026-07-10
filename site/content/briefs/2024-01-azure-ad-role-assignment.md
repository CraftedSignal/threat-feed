---
title: Detection of Privileged Azure AD Role Assignment
slug: 2024-01-azure-ad-role-assignment
description: Detection of privileged Azure AD role assignments to users, which can indicate persistence and privilege escalation by threat actors.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azuread
  - privilege-escalation
  - persistence
  - cloud
vendors:
  - Microsoft
products:
  - Azure Active Directory
  - Microsoft 365
  - Azure
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
  - https://docs.microsoft.com/en-us/azure/active-directory/roles/concept-understand-roles
  - https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference
  - https://adsecurity.org/?p=4277
  - https://www.mandiant.com/resources/detecting-microsoft-365-azure-active-directory-backdoors
  - https://docs.microsoft.com/en-us/azure/active-directory/roles/security-planning
  - https://attack.mitre.org/techniques/T1098/003/
rules:
  - title: Azure AD Privileged Role Assigned
    description: Detects the assignment of privileged Azure AD roles to a user based on Azure AD audit logs.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - audit
      - azure
      - azuread
  - title: Azure AD Role Assignment by Unfamiliar User
    description: Detects role assignments by users that are not typically seen assigning roles.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - audit
      - azure
      - azuread
rules_count: 2
---

This brief addresses the threat of unauthorized or malicious assignment of privileged roles in Azure Active Directory (Azure AD). Threat actors may compromise user accounts and subsequently assign them privileged roles to maintain persistence, escalate privileges, and gain long-term control over the Azure AD environment. The technique involves manipulating user roles to gain administrative access, potentially leading to data breaches, service disruption, or further lateral movement within the cloud environment. This activity can be detected by monitoring Azure AD audit logs for "Add member to role" operations. Successful exploitation can enable the adversary to establish backdoors, exfiltrate sensitive data, or disrupt critical business processes.

## Attack Chain

1.  An attacker gains initial access to a low-privilege user account through credential theft or phishing.
2.  The attacker attempts to assign a privileged role, such as Global Administrator or Security Administrator, to the compromised account. This is done by calling the Azure AD API or using the Azure portal.
3.  The "Add member to role" operation is logged in the Azure AD audit logs.
4.  The system checks if the user attempting the role assignment has the necessary permissions to perform this action. If not, the attempt fails (detection opportunity).
5.  If the attacker has sufficient permissions (e.g., they compromised an account that can assign roles), the privileged role is successfully assigned to the compromised account.
6.  The attacker leverages the newly assigned privileged role to access sensitive data, modify configurations, or create new administrative accounts.
7.  The attacker establishes persistence by creating backdoors, such as adding new service principals with elevated permissions.
8.  The attacker exfiltrates sensitive data or performs other malicious activities using the compromised account with the newly acquired privileges.

## Impact

Successful assignment of privileged roles in Azure AD can have severe consequences. Attackers can gain complete control over the Azure AD tenant, potentially impacting thousands of users and applications. Data breaches, service disruptions, and financial losses are all possible outcomes. The compromised account can be used to create new administrative accounts, further solidifying the attacker's foothold. The impact extends to all services integrated with Azure AD, including Microsoft 365, Azure resources, and other cloud applications.

## Recommendation

*   Deploy the Sigma rule `Azure AD Privileged Role Assigned` to your SIEM to detect unauthorized role assignments based on the `azure:monitor:aad` sourcetype.
*   Investigate any detected instances of privileged role assignments, focusing on the `user` and `initiatedBy` fields to identify potentially compromised accounts.
*   Review and harden Azure AD role assignment policies to minimize the risk of unauthorized privilege escalation, referencing the Microsoft documentation links in the references section.
*   Enable multi-factor authentication (MFA) for all users, especially those with administrative privileges, to mitigate the risk of credential theft.
*   Regularly audit Azure AD role assignments to identify and remove any unnecessary privileges, referencing the MITRE ATT&CK technique T1098.003.
