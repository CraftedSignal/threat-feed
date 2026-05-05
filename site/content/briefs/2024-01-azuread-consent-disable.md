---
title: Azure AD Risk-Based Consent Disabled
slug: 2024-01-azuread-consent-disable
description: The analytic detects when the risk-based step-up consent security setting in Azure AD is disabled by monitoring Azure Active Directory logs for the 'Update authorization policy' operation and changes to the 'AllowUserConsentForRiskyApps' setting, potentially exposing organizations to OAuth phishing attacks.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - oauth
  - consent
  - phishing
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://attack.mitre.org/techniques/T1562/
  - https://goodworkaround.com/2020/10/19/a-look-behind-the-azure-ad-permission-classifications-preview/
  - https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-risk-based-step-up-consent
  - https://learn.microsoft.com/en-us/defender-cloud-apps/investigate-risky-oauth
rules:
  - title: Azure AD Block User Consent For Risky Apps Disabled
    description: Detects when the risk-based step-up consent security setting in Azure AD is disabled by monitoring Azure Active Directory logs for the 'Update authorization policy' operation and changes to the 'AllowUserConsentForRiskyApps' setting.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - cloudtrail
      - azure
      - o365
  - title: Azure AD Update Authorization Policy
    description: Detects any updates to the Azure AD authorization policy
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - cloudtrail
      - azure
      - o365
rules_count: 2
---

This detection identifies instances where the risk-based step-up consent feature in Azure Active Directory (Azure AD) is disabled. The feature, designed to mitigate OAuth phishing attacks by prompting users with extra verification steps when consenting to risky applications, is disabled when the 'AllowUserConsentForRiskyApps' setting is set to 'true'. Attackers can exploit this misconfiguration to trick users into granting malicious applications access to sensitive data. This activity is detected by analyzing Azure AD audit logs for the "Update authorization policy" operation, specifically looking for modifications to the 'AllowUserConsentForRiskyApps' setting. Successful exploitation can lead to unauthorized access, data breaches, and further compromise within the organization.

## Attack Chain

1.  An attacker identifies a target organization using Azure AD and seeks to compromise user accounts.
2.  The attacker crafts a malicious OAuth application designed to harvest user credentials or gain access to sensitive data.
3.  The attacker disables the "risk-based step-up consent" feature in the target Azure AD tenant by modifying the 'AllowUserConsentForRiskyApps' setting to 'true' via the "Update authorization policy" operation.
4.  The attacker distributes the malicious OAuth application via phishing emails or other social engineering techniques.
5.  Unsuspecting users click on the malicious link and are prompted to grant consent to the application without risk-based step-up verification.
6.  Upon granting consent, the malicious application gains access to the user's data and resources within the Azure AD environment.
7.  The attacker uses the compromised account to access sensitive information, escalate privileges, or move laterally within the organization.

## Impact

Disabling the risk-based step-up consent feature in Azure AD can significantly increase the risk of successful OAuth phishing attacks. Successful exploitation could lead to unauthorized access to user data and sensitive information, leading to data breaches and further compromise within the organization. The number of affected users and the extent of data loss depend on the scope of the attack and the permissions granted to the malicious application.

## Recommendation

*   Enable the provided Sigma rule to detect when the 'AllowUserConsentForRiskyApps' setting is enabled, indicating the risk-based step-up consent feature has been disabled.
*   Review Azure AD audit logs for instances of the "Update authorization policy" operation that modify the 'AllowUserConsentForRiskyApps' setting.
*   Investigate and validate any changes to the 'AllowUserConsentForRiskyApps' setting to ensure they are authorized and legitimate.
*   Implement multi-factor authentication (MFA) for all users to reduce the risk of account compromise.
*   Educate users about the risks of OAuth phishing and how to identify suspicious applications.
