---
title: Azure AD Privileged Authentication Administrator Role Assignment Detected
slug: 2024-01-azuread-privauthadmin-role
description: An adversary assigning the 'Privileged Authentication Administrator' role to an account in Azure AD could abuse the new privileges to reset authentication methods for privileged accounts, leading to account takeover and privilege escalation.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - azuread
  - privilege-escalation
  - role-assignment
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#privileged-authentication-administrator
  - https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48
  - https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference
rules:
  - title: Azure AD - Privileged Authentication Administrator Role Assigned
    description: Detects the assignment of the Privileged Authentication Administrator role to a user in Azure AD.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - authentication
      - azure
  - title: Azure AD - Potential Privileged Authentication Administrator Abuse
    description: Detects password reset activity potentially related to Privileged Authentication Administrator abuse
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.002
    data_sources:
      - authentication
      - azure
rules_count: 2
---

The 'Privileged Authentication Administrator' role within Azure Active Directory (Azure AD) grants significant control over user authentication methods. This role allows an assigned user to modify or reset authentication factors (e.g., MFA, passwords) for other users within the tenant, including highly privileged roles like Global Administrators. An adversary gaining this role could exploit it to compromise other accounts by resetting their credentials, bypassing multi-factor authentication, and assuming their identity to perform malicious actions. This poses a severe risk to the confidentiality, integrity, and availability of resources within the Azure AD environment. The activity is detected via Azure AD audit logs.

## Attack Chain

1.  An adversary gains initial access to a low-privileged account within the Azure AD tenant.
2.  The adversary attempts to elevate their privileges by assigning themselves the 'Privileged Authentication Administrator' role. This action is logged as an "Add member to role" event in Azure AD audit logs.
3.  The adversary leverages their new privileges to reset the authentication methods for a high-value target account (e.g., Global Administrator).
4.  The adversary sets a new password or modifies MFA settings for the target account, effectively locking out the legitimate owner.
5.  The adversary uses the newly acquired credentials to log in as the compromised high-value target account.
6.  The adversary performs actions with the privileges of the compromised account, such as modifying critical configurations or accessing sensitive data.
7.  The adversary disables auditing or other security controls to evade detection.

## Impact

Successful exploitation leads to a complete compromise of the Azure AD tenant. An attacker can gain full control over the environment by compromising highly privileged accounts and changing configurations, disabling security features, accessing sensitive data, and potentially disrupting business operations. This can result in significant financial losses, reputational damage, and legal liabilities.

## Recommendation

*   Deploy the provided Sigma rule to detect unauthorized assignments of the 'Privileged Authentication Administrator' role (Azure AD audit logs, `azure_monitor_aad` sourcetype).
*   Review existing assignments of the 'Privileged Authentication Administrator' role and remove any unnecessary or suspicious assignments.
*   Implement multi-factor authentication (MFA) for all users, especially those with privileged roles, and enforce strong password policies.
*   Monitor Azure AD audit logs for suspicious activity related to password resets or authentication method modifications.
*   Investigate and remediate any detected instances of unauthorized role assignments.
