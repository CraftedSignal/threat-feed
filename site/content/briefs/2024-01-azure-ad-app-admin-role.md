---
title: Azure AD Application Administrator Role Assigned to User
slug: 2024-01-azure-ad-app-admin-role
description: An adversary may assign the Azure AD Application Administrator role to a user account for privilege escalation and application credential management, potentially leading to sensitive resource access and tenant compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azuread
  - privilege-escalation
  - role-assignment
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
  - https://dirkjanm.io/azure-ad-privilege-escalation-application-admin/
  - https://posts.specterops.io/azure-privilege-escalation-via-service-principal-abuse-210ae2be2a5
  - https://docs.microsoft.com/en-us/azure/active-directory/roles/concept-understand-roles
  - https://attack.mitre.org/techniques/T1098/003/
  - https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#application-administrator
rules:
  - title: Azure AD Application Administrator Role Assigned
    description: Detects the assignment of the Application Administrator role to a user in Azure AD.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1098.003
    data_sources:
      - cloudtrail
      - azure
      - azuread
  - title: Azure AD Admin Role Assigned to Unusual User Agent
    description: Detects admin role assignments performed via unusual user agents
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098.003
    data_sources:
      - cloudtrail
      - azure
      - azuread
rules_count: 2
---

The assignment of the Application Administrator role in Azure Active Directory (Azure AD) is a critical security event.  Attackers may leverage this role to gain control over enterprise applications within the Azure AD tenant.  The Application Administrator role grants broad permissions to manage all aspects of enterprise applications, including their credentials. By assigning this role to a compromised account or a newly created malicious account, adversaries can manipulate application settings, impersonate application identities, and ultimately access sensitive data. This technique is observed in various attack scenarios targeting cloud environments, particularly those involving privilege escalation. This detection focuses on identifying instances of the "Add member to role" operation within Azure AD audit logs, specifically targeting the Application Administrator role assignment, as described in the Splunk analytic esu-eac4de87-7a56-4538-a21b-277897af6d8d. Defenders should prioritize monitoring and alerting on such role assignments.

## Attack Chain

1.  **Initial Compromise:** The attacker gains initial access to an Azure AD user account, potentially through phishing, credential stuffing, or other means.
2.  **Privilege Escalation Preparation:** The attacker identifies the Application Administrator role as a means to escalate privileges within the Azure AD tenant.
3.  **Role Assignment Request:** The attacker, using the compromised account, initiates a request to assign the Application Administrator role to either the compromised account itself or a different account under their control. This triggers an "Add member to role" event in Azure AD audit logs.
4.  **Role Assignment Execution:** Azure AD processes the role assignment request, granting the specified account the Application Administrator role.
5.  **Application Credential Access:** With the elevated privileges, the attacker accesses the credentials (secrets, certificates) of various enterprise applications registered in Azure AD.
6.  **Application Impersonation:** The attacker uses the acquired application credentials to impersonate the application identities.
7.  **Data Access and Exfiltration:**  Impersonating the applications, the attacker accesses sensitive resources and data that the applications have permissions to access, potentially leading to data exfiltration.
8.  **Lateral Movement:** The attacker leverages application access to move laterally to other resources or applications within the environment.

## Impact

Successful exploitation can lead to complete compromise of enterprise applications managed within Azure AD.  Attackers can steal sensitive data, disrupt business operations, and establish persistent backdoors.  The broad permissions granted by the Application Administrator role make it a high-value target for attackers seeking to escalate privileges and gain unauthorized access to critical resources. A single compromised application can serve as a pivot point for further attacks within the environment.

## Recommendation

*   Deploy the provided Sigma rule `Azure AD Application Administrator Role Assigned` to your SIEM, ensuring proper configuration of the `azure_monitor_aad` macro and tuning for your environment.
*   Review existing Application Administrator role assignments and remove any unnecessary or suspicious assignments.
*   Investigate any alerts generated by the Sigma rule by examining the source and destination user accounts involved in the role assignment (from the `user` and `initiatedBy` fields in the logs) and related activity.
*   Implement multi-factor authentication (MFA) for all user accounts, especially those with administrative privileges.
*   Monitor Azure AD audit logs for any modifications to application credentials or settings.
*   Consult Microsoft's documentation on Azure AD roles and permissions to understand the least privilege principle and apply it to role assignments.
