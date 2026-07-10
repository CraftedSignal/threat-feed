---
title: O365 Risk-Based Consent Disabled
slug: 2024-01-o365-risky-consent
description: The disabling of the 'risk-based step-up consent' security setting in Microsoft 365 allows users to grant consent to potentially malicious applications, increasing the risk of OAuth phishing and unauthorized access to sensitive data.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - o365
  - azuread
  - oauth
  - consent-phishing
  - defense-evasion
vendors:
  - Microsoft
products:
  - Microsoft 365
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
  - title: O365 Block User Consent For Risky Apps Disabled
    description: Detects when the 'risk-based step-up consent' security setting in Microsoft 365 is disabled.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - audit
      - o365
  - title: O365 Update Authorization Policy
    description: Detects any update to O365 Authorization Policy
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - audit
      - o365
rules_count: 2
---

This alert focuses on the disabling of the "risk-based step-up consent" feature within Microsoft 365. When enabled, this feature requires additional authorization steps for users attempting to grant permissions to applications deemed risky by Microsoft. Attackers can exploit user consent to gain access to sensitive data. By disabling this control, adversaries can potentially trick users into granting permissions to malicious applications without triggering additional security checks, effectively bypassing a critical defense mechanism. This can lead to account takeover and data exfiltration. The activity is logged within Azure Active Directory and can be identified by changes to the 'AllowUserConsentForRiskyApps' setting.

## Attack Chain

1.  An attacker gains initial access to an administrator account, potentially through phishing or credential stuffing.
2.  The attacker authenticates to the Azure Active Directory admin portal.
3.  The attacker navigates to the Enterprise applications settings.
4.  The attacker modifies the authorization policy using the "Update authorization policy" operation.
5.  Specifically, the attacker changes the "AllowUserConsentForRiskyApps" setting from "true" to "false".
6.  This change disables the risk-based step-up consent feature, lowering the threshold for application consent.
7.  The attacker then uses social engineering or other phishing techniques to trick users into granting consent to a malicious OAuth application.
8.  Upon successful consent, the attacker gains access to user data and other resources authorized by the user, leading to data theft or further compromise.

## Impact

Disabling risk-based step-up consent can significantly broaden the attack surface within an organization's Microsoft 365 environment. Successful exploitation can lead to widespread data breaches, impacting potentially thousands of users. This can lead to regulatory fines, legal liabilities, and significant reputational damage. The lack of step-up consent increases the likelihood of successful OAuth phishing attacks, which are becoming increasingly prevalent.

## Recommendation

*   Enable the Sysmon config and ingest O365 management activity events to allow for proper detection coverage.
*   Deploy the Sigma rule `O365 Block User Consent For Risky Apps Disabled` in your SIEM to detect instances where the "risk-based step-up consent" setting is disabled.
*   Investigate any detected instances of this setting being disabled, focusing on the user (`user` field in the logs) who made the change and the context surrounding the event.
*   Educate users about the risks associated with granting application consent and how to identify potentially malicious applications.
