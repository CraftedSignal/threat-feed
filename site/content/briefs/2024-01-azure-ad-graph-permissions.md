---
title: Azure AD Privileged Graph API Permission Assignment
slug: 2024-01-azure-ad-graph-permissions
description: Detection of high-risk Graph API permission assignments (Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, and RoleManagement.ReadWrite.Directory) in Azure AD, potentially leading to unauthorized modifications and security breaches.
date: "2024-01-29T12:00:00Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - NOBELIUM Group
tags:
  - azuread
  - cloud
  - graphapi
  - privilegeescalation
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
references:
  - https://cloudbrothers.info/en/azure-attack-paths/
  - https://github.com/mandiant/Mandiant-Azure-AD-Investigator/blob/master/MandiantAzureADInvestigator.json
  - https://learn.microsoft.com/en-us/graph/permissions-reference
  - https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/
  - https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48
rules:
  - title: Azure AD Privileged Graph API Permission Assigned
    description: Detects the assignment of high-risk Graph API permissions in Azure AD audit logs.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1098.003
    data_sources:
      - audit
      - azure
      - azuread
  - title: Azure AD Application Update - Non Privileged Permission Change
    description: Detects any update to Azure AD application permissions excluding high risk API permissions.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1098.003
    data_sources:
      - audit
      - azure
      - azuread
rules_count: 2
---

This threat brief focuses on the assignment of privileged Graph API permissions within Azure Active Directory (Azure AD). Attackers, including groups like NOBELIUM, may attempt to assign themselves or compromised applications excessive permissions to maintain persistence, escalate privileges, or achieve other malicious objectives within the cloud environment. The permissions of concern are Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, and RoleManagement.ReadWrite.Directory, as these grant broad control over applications, role assignments, and directory settings. The detection leverages Azure AD audit logs specifically monitoring 'Update application' operations. Successful exploitation can lead to unauthorized modifications and potential security breaches, compromising the integrity and security of the Azure AD environment. This activity became particularly relevant after the Midnight Blizzard attack, highlighting the need for robust monitoring of Azure AD permission changes.

## Attack Chain

1. An attacker gains initial access to an Azure AD account, possibly through credential theft or phishing.
2. The attacker authenticates to the Azure portal or uses the Azure CLI with the compromised account.
3. The attacker identifies an existing application registration within Azure AD that they can modify.
4. Using the compromised account, the attacker attempts to update the application registration.
5. The attacker assigns one or more of the following high-risk Graph API permissions to the application: Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, or RoleManagement.ReadWrite.Directory. This involves modifying the `requiredAppPermissions` property of the application object.
6. The Azure AD audit log records an "Update application" event with the modified `requiredAppPermissions`.
7. The attacker uses the application's newly acquired permissions to perform malicious actions, such as reading or modifying application configurations, role assignments, or directory settings.
8. The attacker maintains persistence by leveraging the application's elevated privileges for ongoing unauthorized access and control.

## Impact

Successful assignment of these permissions can lead to a complete compromise of the Azure AD environment. An attacker can modify application configurations, create or delete users, assign roles, and potentially gain access to other connected resources and services. The impact can range from data breaches and service disruption to complete control over the organization's cloud identity infrastructure. This is a critical issue, especially in light of recent nation-state attacks targeting Azure AD, as highlighted by Microsoft's guidance on the Midnight Blizzard attack.

## Recommendation

*   Deploy the provided Sigma rule `Azure AD Privileged Graph API Permission Assigned` to your SIEM, ensuring it is tuned to your environment, and enable the data source: `azure_monitor_aad` with category `AuditLogs`.
*   Investigate any alerts triggered by the Sigma rule `Azure AD Privileged Graph API Permission Assigned` immediately to determine if the permission assignment was authorized.
*   Review application registrations in Azure AD and identify any applications with excessive or unnecessary permissions.
*   Monitor Azure AD audit logs for any modifications to application registrations, focusing on changes to the `requiredAppPermissions` property.
*   Implement multi-factor authentication (MFA) for all user accounts, especially those with administrative privileges, to mitigate the risk of credential theft.
