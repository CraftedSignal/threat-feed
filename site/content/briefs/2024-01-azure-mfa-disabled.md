---
title: Azure AD MFA Disabled to Bypass Authentication
slug: 2024-01-azure-mfa-disabled
description: An adversary may disable multi-factor authentication (MFA) in Azure Active Directory to weaken an organization's security posture and bypass authentication mechanisms, potentially gaining unauthorized access to sensitive resources and maintaining persistence.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - mfa
  - credential-access
  - persistence
  - defense-impairment
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-userstates
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_mfa_disabled.yml
rules:
  - title: Azure AD MFA Disabled
    description: Detects when multi-factor authentication is disabled in Azure AD.
    platform: sigma
    severity: medium
    tactics:
      - credential-access
      - defense-impairment
      - persistence
    techniques:
      - T1556
    data_sources:
      - azure
      - activitylogs
  - title: Azure AD MFA Disabled by Unusual Account
    description: Detects when multi-factor authentication is disabled in Azure AD by an account that does not typically perform administrative tasks.
    platform: sigma
    severity: high
    tactics:
      - credential-access
      - defense-impairment
      - persistence
    techniques:
      - T1556
    data_sources:
      - azure
      - activitylogs
rules_count: 2
---

Attackers may disable multi-factor authentication (MFA) within Azure Active Directory (Azure AD) to bypass security controls and gain unauthorized access to user accounts and resources. This activity can occur after initial compromise or as part of an insider threat scenario. The disabling of MFA typically manifests as a successful "Disable Strong Authentication" event within the Azure Active Directory activity logs. Defenders should monitor for these events, especially when initiated by accounts that do not typically perform administrative functions, as it may indicate malicious activity aimed at weakening the organization's security posture and establishing persistence.

## Attack Chain

1. An attacker gains initial access to an account with sufficient privileges in Azure AD, possibly through credential compromise or phishing.
2. The attacker authenticates to the Azure portal or uses Azure AD PowerShell modules.
3. The attacker identifies target user accounts for which they wish to disable MFA.
4. The attacker disables MFA for the targeted user accounts, resulting in an "Disable Strong Authentication." event in the Azure AD activity logs.
5. The attacker attempts to authenticate to the targeted user accounts without MFA.
6. If successful, the attacker gains access to sensitive resources, such as email, files, or applications.
7. The attacker may then move laterally within the environment, accessing additional resources and escalating privileges.

## Impact

Disabling MFA can significantly weaken an organization's security posture, leading to unauthorized access to sensitive data and systems. Successful exploitation could result in data breaches, financial loss, and reputational damage. The impact is widespread, affecting any organization that relies on Azure AD for identity and access management, impacting potentially thousands of users and applications.

## Recommendation

*   Deploy the provided Sigma rule to detect instances of MFA being disabled in Azure AD activity logs, focusing on "Disable Strong Authentication" events (`eventSource: AzureActiveDirectory`, `eventName: 'Disable Strong Authentication.'`).
*   Investigate any detected instances of MFA being disabled, especially if the activity is performed by unusual accounts.
*   Implement multi-factor authentication (MFA) policies and monitor for unauthorized changes to MFA settings.
*   Review and enforce the principle of least privilege for Azure AD roles and permissions.
*   Enable logging for Azure Active Directory activity and sign-in logs (`product: azure`, `service: activitylogs`).
