---
title: Azure AD Multiple Denied MFA Requests Indicating Potential Account Compromise
slug: 2024-01-azure-ad-mfa-denial
description: Detection of an unusually high number of denied MFA requests for a single user within a short timeframe in Azure AD, potentially indicating a targeted account compromise attempt.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azuread
  - mfa
  - account-compromise
  - credential-access
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1621
    technique_name: Multi-Factor Authentication Request Generation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://www.mandiant.com/resources/blog/russian-targeting-gov-business
  - https://arstechnica.com/information-technology/2022/03/lapsus-and-solar-winds-hackers-both-use-the-same-old-trick-to-bypass-mfa/
  - https://therecord.media/russian-hackers-bypass-2fa-by-annoying-victims-with-repeated-push-notifications/
  - https://attack.mitre.org/techniques/T1621/
  - https://attack.mitre.org/techniques/T1078/004/
  - https://www.cisa.gov/sites/default/files/publications/fact-sheet-implement-number-matching-in-mfa-applications-508c.pdf
rules:
  - title: Azure AD Multiple Denied MFA Requests
    description: Detects multiple denied MFA requests for a single user within a 10-minute window, indicating a potential MFA fatigue attack.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1078.004
      - T1621
    data_sources:
      - network_connection
      - azure
  - title: Azure AD MFA Denied with Error Code 500121
    description: Detects MFA denial events with error code 500121, indicating the user declined the authentication.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1621
    data_sources:
      - network_connection
      - azure
rules_count: 2
---

This threat brief addresses the potential for account compromise in Azure Active Directory (Azure AD) environments, specifically focusing on scenarios where an attacker attempts to bypass multi-factor authentication (MFA) by repeatedly sending MFA requests to a legitimate user until they are either accepted or the user becomes desensitized and approves a fraudulent request. This technique is often employed after an attacker has gained initial access through methods like password spraying or phishing. The detection focuses on identifying instances where a user has denied more than nine MFA requests within a 10-minute window. While the specific actor is unknown, the technique aligns with observed behaviors from various threat actors, including those detailed by Mandiant and in reports related to LAPSUS$ and SolarWinds breaches. This activity is critical for defenders as a successful MFA bypass can lead to significant data breaches, lateral movement within the organization, and further malicious activities. The original Splunk analytic was published on 2026-04-17.

## Attack Chain

1.  The attacker gains initial access to a valid user's credentials through phishing, password spraying, or credential stuffing.
2.  The attacker attempts to authenticate to Azure AD using the compromised credentials.
3.  Azure AD prompts the legitimate user for MFA verification.
4.  The user denies the MFA request, recognizing the unauthorized login attempt.
5.  The attacker repeatedly initiates login attempts, triggering multiple MFA requests in a short period.
6.  The user continues to deny the MFA requests, but the sheer volume may cause confusion or fatigue.
7.  If the attacker successfully convinces the user to approve a request, or exploits a vulnerability to bypass MFA, they gain access to the user's account.
8.  With compromised credentials, the attacker performs actions such as accessing sensitive data, moving laterally to other systems, or deploying malware.

## Impact

A successful MFA bypass can have significant consequences, including unauthorized access to sensitive data, lateral movement within the organization's network, and the potential deployment of ransomware or other malware. Organizations in any sector could be targeted, with potential impacts ranging from data breaches and financial losses to reputational damage and disruption of services. The number of affected users and the scale of the damage will vary depending on the attacker's objectives and the organization's security posture. This technique is especially effective against users who are not trained to recognize and report suspicious MFA requests, and organizations that haven't implemented number matching.

## Recommendation

*   Deploy the Sigma rule `Azure AD Multiple Denied MFA Requests` to detect potential MFA fatigue attacks based on Azure AD Sign-in logs (logsource: category: `network_connection`, product: `azure`).
*   Implement number matching in MFA applications as recommended by CISA to mitigate MFA bypass techniques ([https://www.cisa.gov/sites/default/files/publications/fact-sheet-implement-number-matching-in-mfa-applications-508c.pdf](https://www.cisa.gov/sites/default/files/publications/fact-sheet-implement-number-matching-in-mfa-applications-508c.pdf)).
*   Investigate and filter out known false positives, such as authentication errors, as described in the documentation for the original Splunk detection.
*   Review and enhance user training programs to educate employees on recognizing and reporting suspicious MFA requests.
