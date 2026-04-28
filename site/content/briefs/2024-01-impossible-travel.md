---
title: Impossible Travel Detection in Azure AD
slug: 2024-01-impossible-travel
description: This brief describes the detection of 'impossible travel' events in Azure AD, where a user appears to log in from geographically distant locations within an implausibly short time frame, potentially indicating account compromise.
date: "2024-01-02T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - azuread
  - identity-protection
  - impossible-travel
  - account-compromise
  - lateral-movement
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#impossible-travel
  - https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins
rules:
  - title: Azure AD Impossible Travel Detection
    description: Detects user activities originating from geographically distant locations within a time period shorter than the time it takes to travel from the first location to the second, as reported by Azure AD Identity Protection.
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
  - title: Azure AD Risky Sign-in Detected
    description: Detects when a risky sign-in is detected in Azure AD.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
    techniques:
      - T1078
    data_sources:
      - azure
      - riskdetection
rules_count: 2
---

This rule detects "impossible travel" events within Azure Active Directory (Azure AD), a common indicator of account compromise. The scenario involves a user account exhibiting login activity from two geographically distant locations in a timeframe that makes physical travel between them impossible. This anomalous behavior often signifies that an attacker has gained unauthorized access to the account and is operating from a different location than the legitimate user. The rule leverages Azure AD Identity Protection's risk detection capabilities to identify such instances. This detection is crucial for defenders as it highlights potential breaches and enables swift remediation actions to prevent further damage.

## Attack Chain

1.  An attacker gains initial access to a user's credentials, potentially through phishing (T1566), credential stuffing, or malware.
2.  The attacker authenticates to Azure AD from a geographic location different from the legitimate user's typical location.
3.  Shortly after the initial authentication, the legitimate user authenticates to Azure AD from their usual location.
4.  Azure AD Identity Protection flags the activity as "impossible travel" due to the conflicting geographic locations and the short timeframe between the authentications.
5.  The "impossibleTravel" risk event is logged within Azure AD's risk detection logs.
6.  The attacker may attempt to escalate privileges within the compromised account (T1068) to gain broader access to resources.
7.  The attacker may move laterally within the organization (T1021) to access sensitive data or systems.
8.  The attacker's ultimate goal could be data exfiltration, financial theft, or disruption of services, depending on the organization's profile.

## Impact

A successful "impossible travel" attack can lead to a full compromise of the user's account, granting the attacker access to sensitive data, internal systems, and other resources accessible to the user. Depending on the user's role and permissions, the impact could range from data breaches to financial losses and significant reputational damage. Organizations in all sectors are vulnerable, with a higher risk for those handling sensitive data or operating critical infrastructure. The number of affected users depends on the attacker's ability to move laterally and escalate privileges after compromising the initial account.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect "impossible travel" events flagged by Azure AD Identity Protection, focusing on the `riskEventType: 'impossibleTravel'` (logsource: azure, service: riskdetection).
*   Investigate any triggered alerts promptly, focusing on the user account involved and the geographic locations of the login attempts (logsource: azure, service: riskdetection).
*   Review and enhance user training programs to educate employees on the risks of phishing and credential compromise (T1566).
*   Implement multi-factor authentication (MFA) for all users to mitigate the risk of unauthorized access even if credentials are compromised (T1110).
*   Review and adjust the sensitivity of Azure AD Identity Protection's risk detection policies to align with your organization's risk tolerance.
*   Consider implementing conditional access policies that restrict access based on geographic location or require MFA for logins from unfamiliar locations.
