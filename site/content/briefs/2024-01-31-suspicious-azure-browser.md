---
title: Azure Identity Protection Suspicious Browser Activity
slug: 2024-01-31-suspicious-azure-browser
description: A suspicious browser activity alert indicates anomalous behavior based on suspicious sign-in activity across multiple tenants from different countries in the same browser, potentially indicating compromised credentials or other malicious activity.
date: "2024-01-31T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - azure
  - identity-protection
  - suspicious-browser
vendors:
  - Microsoft
products:
  - Azure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
references:
  - https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#suspicious-browser
  - https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins
rules:
  - title: Azure AD Identity Protection Suspicious Browser Activity
    description: Detects suspicious browser activity based on Azure AD Identity Protection alerts.
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
    description: Detects risky sign-in activity based on Azure AD Identity Protection alerts.
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

The "suspiciousBrowser" risk event in Azure Identity Protection signals unusual sign-in patterns indicative of potential account compromise or other malicious activity. This alert is triggered when the same browser is used to access multiple tenants from different countries, which is an atypical behavior for legitimate users. This type of activity could be caused by malware, credential theft, or an attacker attempting to blend in with normal user behavior after gaining unauthorized access. This detection is important for defenders because it can highlight early stages of an attack, potentially preventing lateral movement, data exfiltration, or other damaging actions.

## Attack Chain

1. An attacker gains initial access to a user's credentials through phishing, malware, or other means (T1566, T1190).
2. The attacker configures a browser with the stolen credentials.
3. The attacker uses the same browser to attempt sign-ins to multiple Azure tenants from different geographical locations, attempting to blend in with typical user activity.
4. Azure Identity Protection detects the "suspiciousBrowser" risk event based on the anomalous sign-in activity.
5. If successful, the attacker may gain access to sensitive data and resources within the targeted tenants.
6. The attacker leverages the compromised accounts to escalate privileges and move laterally within the organization (T1078, T1068).
7. The attacker exfiltrates sensitive data or deploy ransomware (T1003, T1486).

## Impact

A successful attack exploiting suspicious browser activity can lead to unauthorized access to multiple Azure tenants, potentially impacting numerous organizations. The compromise of user accounts can result in data breaches, financial losses, and reputational damage. The scope of the impact depends on the level of access granted to the compromised accounts and the sensitivity of the data stored within the targeted tenants.

## Recommendation

*   Deploy the provided Sigma rule to detect "suspiciousBrowser" risk events in your Azure environment and tune for your environment.
*   Investigate sessions flagged by this detection in the context of other sign-ins from the same user to identify false positives.
*   Enforce multi-factor authentication (MFA) to mitigate the impact of compromised credentials.
*   Monitor user sign-in activity for unusual patterns, such as sign-ins from multiple geographical locations within a short period.
