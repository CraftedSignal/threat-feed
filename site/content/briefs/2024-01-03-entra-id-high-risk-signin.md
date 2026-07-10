---
title: Entra ID High Risk Sign-in Detected
slug: 2024-01-03-entra-id-high-risk-signin
description: This rule detects high-risk sign-ins in Microsoft Entra ID, as identified by Identity Protection, where the sign-in is flagged with a risk level of `high` during the authentication process, indicating a strong likelihood of account compromise.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - entra_id
  - initial_access
  - high_risk_signin
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-risk
  - https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection
  - https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-investigate-risk
rules:
  - title: Entra ID High Risk Sign-in Detected
    description: Detects high-risk Microsoft Entra ID sign-ins as identified by Identity Protection.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1078.004
    data_sources:
      - network_connection
      - azure
  - title: Entra ID Sign-in from Anonymization Service
    description: Detects Entra ID sign-ins originating from known anonymization services (VPNs, Tor).
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - network_connection
      - azure
rules_count: 2
---

This detection identifies potentially compromised user accounts through the detection of high-risk sign-ins within Microsoft Entra ID. Microsoft's Identity Protection uses machine learning and heuristics to categorize sign-in risk levels as low, medium, or high. A "high" risk level suggests a significant probability of account compromise. This detection focuses on sign-ins flagged as "high" risk during the authentication process, indicating active attacks or compromise attempts using valid credentials. The rule leverages Azure sign-in logs and triggers when the `risk_level_during_signin` or `risk_level_aggregated` properties are set to `high`. The detection logic was last updated on 2026-04-10.

## Attack Chain

1. An attacker gains initial access using compromised credentials (T1078).
2. The attacker attempts to authenticate to Entra ID.
3. Entra ID Identity Protection evaluates the sign-in attempt, factoring in elements such as source IP, geolocation, device details, and authentication method.
4. The sign-in is flagged as "high risk" by Identity Protection due to anomalous characteristics.
5. The sign-in logs record the high-risk level in the `risk_level_during_signin` property.
6. The detection rule triggers based on the high-risk sign-in event.
7. Post-authentication, the attacker potentially gains access to cloud resources and applications (T1078.004).
8. The attacker attempts lateral movement or data exfiltration.

## Impact

A successful attack could lead to unauthorized access to sensitive data, resources, and applications within the organization's cloud environment. The number of affected users and the scope of the damage depend on the permissions and roles assigned to the compromised account. Organizations in any sector relying on Entra ID for authentication are potentially at risk. Failure to detect and remediate high-risk sign-ins can result in significant data breaches, financial losses, and reputational damage.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect high-risk Entra ID sign-ins based on the `azure.signinlogs.properties.risk_level_during_signin` and `azure.signinlogs.properties.risk_level_aggregated` fields.
*   Investigate triggered alerts by reviewing the `source.ip`, `source.geo.country_name`, `device_detail`, and `client_app_used` fields in the Azure sign-in logs.
*   If a compromise is suspected, immediately disable the user account and enforce a password reset with multi-factor authentication.
*   Review and refine conditional access policies to enforce MFA for high-risk sign-ins and block legacy authentication protocols, referencing the information on conditional access policies in the references.
