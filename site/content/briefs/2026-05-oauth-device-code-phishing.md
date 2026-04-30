---
title: Large-Scale OAuth Device Code Phishing Campaign Observed in April 2026
slug: 2026-05-oauth-device-code-phishing
description: In early April 2026, Arctic Wolf tracked a large-scale device code phishing campaign across multiple regions and sectors where threat actors abused OAuth device code flow to trick victims into providing authentication codes.
date: "2026-04-24T19:52:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - oauth
  - device-code
  - phishing
  - initial-access
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://arcticwolf.com/resources/blog/token-bingo-dont-let-your-code-be-the-winner/
rules:
  - title: Detect Suspicious Azure AD Application Registration
    description: Detects the creation of new Azure AD applications with suspicious permissions or settings often used in OAuth phishing attacks.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - configuration
      - o365
  - title: Detect High Volume of Device Code Flow Requests
    description: Detects a high number of device code flow requests originating from a single IP address, which may indicate a phishing campaign.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - authentication
      - azuread
rules_count: 2
---

In early April 2026, Arctic Wolf observed a widespread phishing campaign that abused the OAuth device code flow. This campaign targeted organizations across multiple regions and sectors, mirroring the "Riding the Rails" campaign observed by Huntress in late March. The attackers exploited the device code grant type in the OAuth 2.0 authorization framework to obtain access tokens. By tricking users into entering a code on a legitimate Microsoft login page, attackers bypassed traditional MFA controls. Defenders should be aware of this evolving technique and implement detection strategies focused on anomalous application registrations and device code flow activity.

## Attack Chain

1. The attacker sends a phishing email to the victim, impersonating a legitimate service.
2. The email contains a link that redirects the victim to a fake application authorization page.
3. The fake page prompts the victim to enter a device code.
4. Unbeknownst to the victim, the device code is associated with a malicious OAuth application controlled by the attacker.
5. The victim is redirected to a legitimate Microsoft login page, where they enter the provided code and authenticate.
6. Upon successful authentication, the malicious application receives an access token.
7. The attacker uses the access token to access the victim's account and sensitive data.
8. The attacker may then perform actions such as reading emails, accessing files, or initiating further malicious activity within the compromised account.

## Impact

This OAuth device code phishing campaign affected numerous organizations across multiple sectors and regions in early April 2026. Successful attacks grant threat actors unauthorized access to user accounts, potentially leading to data exfiltration, financial fraud, and further compromise of internal systems. Due to the nature of OAuth, attackers can maintain persistent access even after password changes, posing a significant long-term risk.

## Recommendation

*   Monitor Azure AD sign-in logs for device code flow usage to identify suspicious authentications (logsource: azuread, category: authentication).
*   Implement the Sigma rule provided below to detect suspicious application registrations in Azure AD (logsource: o365, category: configuration).
*   Educate users on the risks of device code phishing and how to identify malicious authorization requests.
*   Regularly audit OAuth applications authorized within your environment and revoke access for any suspicious or unused applications.
*   Investigate any alerts related to anomalous OAuth application activity promptly.
