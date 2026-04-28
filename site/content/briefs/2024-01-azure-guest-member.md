---
title: Azure AD Guest to Member User Type Conversion
slug: 2024-01-azure-guest-member
description: An adversary may convert a guest user account to a member account in Azure Active Directory to elevate privileges and gain persistent access to resources.
date: "2024-01-03T15:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - privilege-escalation
  - azure
  - entra
  - guest-account
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-gb/entra/architecture/security-operations-user-accounts#monitoring-external-user-sign-ins
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_guest_to_member.yml
rules:
  - title: Azure AD Guest to Member Conversion
    description: Detects when a user account's UserType is changed from Guest to Member in Azure AD audit logs.
    platform: sigma
    severity: medium
    tactics:
      - privilege-escalation
    techniques:
      - T1078.004
    data_sources:
      - azure
      - auditlogs
  - title: Azure AD User Type Change Detection
    description: Detects modifications to the UserType attribute in Azure AD audit logs, which may indicate privilege escalation attempts.
    platform: sigma
    severity: low
    tactics:
      - privilege-escalation
    techniques:
      - T1078.004
    data_sources:
      - azure
      - auditlogs
rules_count: 2
---

The conversion of a user account from "Guest" to "Member" within Azure Active Directory (Azure AD) can represent a significant privilege escalation. While legitimate use cases exist for such conversions, malicious actors can abuse this functionality to gain unauthorized access and persistence. By elevating a guest account, which typically has limited permissions, to a member account, attackers can inherit the broader access rights associated with the latter, potentially compromising sensitive data and systems. Monitoring this activity is crucial as it can be indicative of insider threats or compromised administrative accounts used to manipulate user roles.

## Attack Chain

1. **Compromise Initial Account:** An attacker gains initial access, possibly through phishing or credential stuffing, to an account with sufficient privileges to modify user attributes in Azure AD.
2. **Identify Target Guest Account:** The attacker identifies a guest account within the Azure AD environment that could provide valuable access if converted to a member account.
3. **Modify UserType Attribute:** Using the compromised account, the attacker modifies the `UserType` attribute of the target guest account from "Guest" to "Member" via the Azure AD portal, PowerShell, or the Microsoft Graph API. This action generates an "Update user" event in the Azure AD audit logs.
4. **Inherit Member Privileges:** Once the `UserType` is changed to "Member", the account inherits the privileges and group memberships associated with member accounts within the organization.
5. **Lateral Movement:** Leveraging the newly acquired member privileges, the attacker moves laterally within the Azure AD environment, accessing resources and services that were previously inaccessible.
6. **Data Exfiltration or System Compromise:** The attacker uses the elevated privileges to exfiltrate sensitive data, compromise critical systems, or establish persistent backdoors for future access.

## Impact

Successful conversion of a guest account to a member account can lead to significant privilege escalation, potentially granting attackers access to sensitive data, critical systems, and confidential resources. This can lead to data breaches, financial losses, reputational damage, and disruption of business operations. The impact depends on the permissions assigned to member accounts and the sensitivity of the resources they can access.

## Recommendation

*   Deploy the "User State Changed From Guest To Member" Sigma rule to your SIEM to detect unauthorized user type conversions in Azure AD audit logs.
*   Investigate any detected instances of user type changes from "Guest" to "Member" to verify their legitimacy, focusing on the user performing the action and the reason for the change (as captured by the Azure AD audit logs).
*   Implement multi-factor authentication (MFA) for all user accounts, especially those with administrative privileges, to mitigate the risk of account compromise and unauthorized access.
*   Review and enforce the principle of least privilege for all user accounts to minimize the potential impact of a successful privilege escalation attack.
