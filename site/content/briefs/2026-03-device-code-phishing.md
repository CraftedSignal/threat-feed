---
title: Device Code Phishing Campaign Targeting Cloud Platforms
slug: 2026-03-device-code-phishing
description: A phishing campaign abuses Microsoft's Device Code OAuth flow to gain access to cloud-based file storage and document workflow platforms, bypassing traditional credential harvesting.
date: "2026-03-25T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - credential-access
  - initial-access
  - phishing
  - oauth
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://www.reddit.com/r/blueteamsec/comments/1s26zoe/active_device_code_phishing_campaign/
  - https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-03-23-%20Device-Code-based-OAuth-Phishing.txt
rules:
  - title: Detect Suspicious Device Code Authentication
    description: Detects unusual device code authentication activity in Azure AD logs, potentially indicating OAuth phishing attempts.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1189
    data_sources:
      - authentication
      - azure_ad
  - title: Detect New OAuth Application Consent
    description: Detects when a user grants consent to a new OAuth application, which can be indicative of a device code phishing attack.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1189
    data_sources:
      - authentication
      - azure_ad
rules_count: 2
---

An active phishing campaign is leveraging Microsoft's Device Code OAuth flow to target users of cloud-based file storage and document workflow platforms. Unlike traditional phishing attacks that aim to steal usernames and passwords directly, this campaign exploits a legitimate authentication mechanism to gain unauthorized access. The campaign impersonates popular cloud services, enticing users to enter a provided device code on a Microsoft login page. By doing so, victims inadvertently grant the attacker access to their accounts on the targeted platforms. This campaign highlights the evolving tactics of phishing actors and the need for robust detection mechanisms beyond simple credential harvesting alerts. The scope and scale of the campaign are currently unknown.

## Attack Chain

1. The attacker sends a phishing email impersonating a cloud-based file storage or document workflow service.
2. The email contains a message prompting the user to "activate" or "authenticate" their account.
3. The email includes a device code and instructs the user to visit a Microsoft login page (e.g., microsoft.com/devicelogin).
4. The user, believing the request is legitimate, enters the provided device code on the Microsoft login page.
5. The Microsoft login page prompts the user to grant permissions to an application controlled by the attacker.
6. If the user approves the permissions, the attacker gains OAuth tokens that allow access to the user's account on the targeted cloud platform.
7. The attacker can then access, modify, or exfiltrate data stored on the compromised account.
8. The attacker may use the compromised account to further propagate the phishing campaign to other users within the organization.

## Impact

Successful attacks can lead to unauthorized access to sensitive data stored in cloud-based file storage and document workflow platforms. This can result in data breaches, financial loss, and reputational damage for affected organizations. The use of a legitimate Microsoft authentication flow makes this campaign difficult to detect with traditional phishing detection methods. The lack of credential harvesting may also bypass security controls focused on monitoring password theft. The specific number of victims and sectors targeted remains unknown, but the potential impact is significant given the widespread use of cloud services.

## Recommendation

*   Implement user awareness training to educate employees about device code phishing and the risks of entering unknown codes on login pages.
*   Monitor Microsoft Entra ID (Azure AD) logs for unusual device code authentication patterns, focusing on applications requesting broad permissions (reference: Attack Chain steps 5 and 6). Deploy the "Detect Suspicious Device Code Authentication" Sigma rule to identify anomalous activity.
*   Implement Conditional Access policies in Microsoft Entra ID to restrict device code authentication to trusted devices and locations.
*   Investigate any successful device code authentications where the application requesting permissions is not recognized or approved by the organization.
