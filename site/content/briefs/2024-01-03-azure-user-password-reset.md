---
title: Azure AD User Password Reset Detection
slug: 2024-01-03-azure-user-password-reset
description: Detects when a user successfully resets their own password in Azure Active Directory, which may indicate malicious activity or account compromise.
date: "2024-01-03T15:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - azure
  - password-reset
  - privilege-escalation
  - initial-access
  - persistence
  - credential-access
  - stealth
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-accounts
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_user_password_change.yml
rules:
  - title: Azure AD - Password Reset By User Account
    description: Detect when a user has reset their password in Azure AD
    platform: sigma
    severity: medium
    tactics:
      - credential-access
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078.004
    data_sources:
      - azure
      - auditlogs
  - title: Azure AD - Password Reset Failed Attempt
    description: Detect failed attempts to reset a password in Azure AD which may indicate reconnaissance or credential harvesting
    platform: sigma
    severity: low
    tactics:
      - credential-access
      - discovery
      - initial-access
    techniques:
      - T1589
    data_sources:
      - azure
      - auditlogs
rules_count: 2
---

This threat brief focuses on detecting user-initiated password resets within Azure Active Directory (Azure AD). While legitimate password resets are common, monitoring this activity can help identify potentially malicious behavior, such as an attacker attempting to gain unauthorized access to an account or an insider threat actor escalating privileges. Attackers may leverage compromised credentials or social engineering to initiate password resets, bypassing multi-factor authentication (MFA) if it is not properly configured or enforced. This detection is important for defenders because successful password resets can lead to a complete account takeover, allowing attackers to access sensitive data, resources, and systems.

## Attack Chain

1.  An attacker gains initial access to a user's credentials through phishing, credential stuffing, or malware.
2.  The attacker attempts to log in to an Azure AD-protected resource using the compromised credentials.
3.  The attacker fails to authenticate, either because they do not have the correct password or MFA is enabled.
4.  The attacker initiates a password reset request using the "Forgot password" feature or a similar mechanism.
5.  Azure AD sends a password reset verification code or link to the user's registered email address or phone number.
6.  If the attacker controls the registered email address or phone number (due to prior compromise), they can access the verification code or link.
7.  The attacker uses the verification code or link to set a new password for the user's Azure AD account.
8.  The attacker logs in to the Azure AD account with the new password, gaining unauthorized access.

## Impact

Successful password resets by attackers can lead to complete account takeover, allowing them to access sensitive data, resources, and systems protected by Azure AD. This can result in data breaches, financial loss, reputational damage, and disruption of business operations. The impact depends on the privileges and permissions assigned to the compromised account.

## Recommendation

*   Deploy the Sigma rule `Password Reset By User Account` to your SIEM to detect user-initiated password resets in Azure AD audit logs.
*   Investigate any detected password resets, especially those initiated by users who have not recently requested a password change.
*   Review and enforce multi-factor authentication (MFA) policies to prevent attackers from bypassing password-based authentication.
*   Monitor Azure AD audit logs for suspicious activity related to password resets, such as multiple failed login attempts followed by a successful reset.
