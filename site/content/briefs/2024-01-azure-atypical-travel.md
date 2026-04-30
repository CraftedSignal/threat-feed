---
title: Azure Identity Protection Atypical Travel Anomaly
slug: 2024-01-azure-atypical-travel
description: The Atypical Travel detection in Azure Identity Protection identifies potentially compromised user accounts by detecting geographically improbable sign-in activity, indicative of account compromise or misuse.
date: "2024-01-02T18:21:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - identity-protection
  - atypical-travel
  - account-compromise
  - credential-theft
vendors:
  - Microsoft
products:
  - Azure Active Directory
  - Microsoft Entra ID Protection
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#atypical-travel
  - https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins
rules:
  - title: Azure AD Identity Protection - Atypical Travel
    description: Detects Atypical Travel events in Azure AD Identity Protection.
    platform: sigma
    severity: high
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078
    data_sources:
      - azure
      - riskdetection
  - title: Azure AD Identity Protection - Atypical Travel - Multiple Events
    description: Detects multiple Atypical Travel events for the same user within a short period.
    platform: sigma
    severity: high
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078
    data_sources:
      - azure
      - riskdetection
rules_count: 2
---

The Atypical Travel detection in Azure Identity Protection is designed to identify instances where a user signs in from two geographically distant locations within a time frame that makes legitimate travel improbable. This anomaly indicates that an attacker may have compromised a user's credentials and is attempting to access resources from a different location. The alert is triggered by the 'unlikelyTravel' risk event type within Azure's risk detection service. This capability helps defenders identify compromised accounts and prevent further damage such as data exfiltration or lateral movement within the environment. The detection is based on comparing current sign-in locations against the user's historical sign-in patterns, making it more accurate and less prone to false positives compared to simple geo-location based alerts.

## Attack Chain

1. **Credential Compromise:** An attacker obtains a user's credentials through phishing, credential stuffing, or malware.
2. **Initial Access (Location A):** The attacker uses the compromised credentials to sign in from a location that may be atypical for the user.
3. **Successful Authentication (Location A):** The attacker successfully authenticates and gains access to Azure resources.
4. **Privilege Escalation (Optional):** If the compromised account has sufficient permissions, the attacker attempts to escalate privileges within the Azure environment.
5. **Lateral Movement (Optional):** The attacker uses the compromised account to move laterally to other resources or accounts within the Azure environment.
6. **Second Sign-in (Location B):** Within a short timeframe, the attacker (or another attacker using the same credentials) signs in from a geographically distant location (Location B).
7. **Atypical Travel Alert:** Azure Identity Protection detects the unlikely travel scenario based on the two geographically improbable sign-ins.
8. **Resource Access/Data Exfiltration:** The attacker accesses sensitive resources or exfiltrates data from the environment.

## Impact

A successful Atypical Travel attack can lead to unauthorized access to sensitive data, privilege escalation, lateral movement within the Azure environment, and potentially data exfiltration. The number of victims depends on the scope of the compromised user's access and the attacker's objectives. Organizations in all sectors are potentially at risk, as attackers often target user accounts with elevated privileges or access to critical data. The financial impact can include the cost of incident response, data breach notifications, and potential regulatory fines.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect Atypical Travel events (logsource: azure, service: riskdetection).
*   Investigate flagged sessions in the context of other sign-ins from the user, as suggested by the false positives guidance.
*   Implement multi-factor authentication (MFA) for all users to mitigate the risk of credential compromise.
*   Review and enforce conditional access policies to restrict access based on location and other factors.
*   Monitor user accounts for unusual activity, such as changes in sign-in patterns or resource access.
*   Implement account lockout policies to prevent brute-force attacks against user accounts.
