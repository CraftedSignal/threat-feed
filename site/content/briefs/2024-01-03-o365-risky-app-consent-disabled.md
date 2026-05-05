---
title: Microsoft 365 Risk-Based Step-Up Consent Disabled
slug: 2024-01-03-o365-risky-app-consent-disabled
description: The Microsoft 365 'risk-based step-up consent' security setting is disabled by an adversary to allow users to grant consent to malicious applications, potentially leading to unauthorized access and data breaches.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azuread
  - o365
  - oauth
  - risk-based consent
  - defense-evasion
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
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
      - T1562.001
    data_sources:
      - audit
      - o365
  - title: O365 Update Authorization Policy
    description: Detects any updates to the authorization policy in O365.
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

The disabling of the "risk-based step-up consent" feature in Microsoft 365 is a significant security concern. This feature, when enabled, adds an extra layer of security by requiring administrator approval or additional authentication steps when users attempt to grant permissions to applications deemed risky by Microsoft. When disabled, users can grant consent to potentially malicious OAuth applications without any additional checks, increasing the risk of OAuth phishing attacks. An attacker might disable this feature to facilitate easier access to sensitive user data through malicious applications, bypassing security controls implemented to protect the organization. This could be part of a broader attack to compromise user accounts and exfiltrate data.

## Attack Chain

1. An attacker gains initial access to an account with sufficient privileges to modify Azure Active Directory authorization policies.
2. The attacker navigates to the Azure Active Directory settings.
3. The attacker identifies the "risk-based step-up consent" setting.
4. The attacker disables the "AllowUserConsentForRiskyApps" setting by modifying the authorization policy.
5. Users are now able to grant consent to risky OAuth applications without triggering additional security checks.
6. The attacker deploys or promotes a malicious OAuth application, tricking users into granting it permissions.
7. The malicious application gains access to user data and other resources based on the granted permissions.
8. The attacker exfiltrates sensitive data or performs other malicious actions using the compromised application.

## Impact

Disabling the risk-based step-up consent feature can significantly increase the attack surface of a Microsoft 365 environment. If successful, attackers can compromise user accounts and exfiltrate sensitive data. This can lead to financial loss, reputational damage, and legal liabilities. Organizations that fail to monitor and protect this setting are at higher risk of OAuth phishing attacks and subsequent data breaches.

## Recommendation

*   Enable the "risk-based step-up consent" security setting in Microsoft 365 to prevent users from granting consent to risky applications without proper authorization.
*   Deploy the Sigma rule `O365 Block User Consent For Risky Apps Disabled` to your SIEM to detect when this setting is modified.
*   Review Azure Active Directory audit logs for unexpected changes to authorization policies related to application consent.
*   Monitor user activity for OAuth application consent grants, especially to applications from untrusted or unknown publishers.
