---
title: Entra ID OAuth Device Code Phishing via AiTM
slug: 2026-05-entra-device-code-phishing
description: Detects successful Microsoft Entra ID sign-ins using the OAuth device code authentication protocol with the Microsoft Authentication Broker client requesting first-party Office API resources, indicative of adversary-in-the-middle (AiTM) phishing attacks such as Tycoon 2FA.
date: "2026-05-18T10:04:48Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Tycoon2FA
tags:
  - cloud
  - identity
  - azure
  - entra_id
  - phishing
vendors:
  - Microsoft
products:
  - Entra ID
  - Exchange Online
  - Microsoft Graph
  - SharePoint
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://any.run/malware-trends/tycoon/
  - https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows
  - https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/
rules:
  - title: Entra ID OAuth Device Code Phishing via AiTM
    description: Detects successful Microsoft Entra ID sign-ins using the OAuth device code authentication protocol with the Microsoft Authentication Broker client requesting first-party Office API resources, indicative of adversary-in-the-middle (AiTM) phishing attacks.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1550
      - T1566
    data_sources:
      - authentication
      - azure
  - title: Entra ID OAuth Device Code Phishing via AiTM - Non Standard App ID
    description: Detects successful Microsoft Entra ID sign-ins using the OAuth device code authentication protocol with a non-standard App ID, requesting first-party Office API resources.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1550
      - T1566
    data_sources:
      - authentication
      - azure
rules_count: 2
---

This detection identifies a specific pattern associated with adversary-in-the-middle (AiTM) phishing campaigns targeting Microsoft Entra ID. It focuses on successful sign-ins utilizing the OAuth device code authentication protocol in conjunction with the Microsoft Authentication Broker client. A key characteristic is the request for first-party Office API resources, specifically Exchange Online, Microsoft Graph, or SharePoint. The activity is flagged as interactive. This tactic is linked to AiTM phishing kits like Tycoon 2FA, where unsuspecting victims are tricked into completing device code flows, ultimately granting attackers access tokens for mail and collaboration APIs. This allows unauthorized access to sensitive data and resources within the organization's cloud environment. The blog post from Microsoft on February 13, 2025, highlights the Storm-2372 campaign which utilizes this technique.

## Attack Chain

1.  The attacker sends a phishing email or message to the victim containing a link or QR code.
2.  The victim clicks on the link or scans the QR code, which redirects them to a fake Microsoft login page controlled by the attacker.
3.  The fake login page prompts the victim to enter a device code.
4.  The attacker initiates a legitimate OAuth device code flow using the Microsoft Authentication Broker client.
5.  The victim enters the device code on the attacker-controlled page, unknowingly authorizing the attacker's application.
6.  The attacker's application requests access to first-party Office API resources, such as Exchange Online (resource ID 00000002-0000-0ff1-ce00-000000000000), Microsoft Graph (00000003-0000-0ff1-ce00-000000000000), or SharePoint (00000005-0000-0ff1-ce00-000000000000).
7.  The Microsoft Authentication Broker authenticates the request as interactive.
8.  The attacker gains access to the victim's mail and collaboration APIs via the obtained access tokens, enabling data exfiltration and other malicious activities.

## Impact

Successful exploitation leads to unauthorized access to the victim's Microsoft Entra ID account and associated resources, including email, files, and other sensitive data. This can result in data theft, financial loss, and reputational damage to the organization. The Tycoon 2FA kit, as referenced, facilitates this type of attack, bypassing traditional multi-factor authentication methods. The scale of impact depends on the scope of access granted to the compromised account.

## Recommendation

*   Deploy the Sigma rule "Entra ID OAuth Device Code Phishing via AiTM" to your SIEM to detect suspicious device code authentication flows.
*   Investigate any alerts triggered by the Sigma rule, focusing on `azure.signinlogs.properties.user_principal_name`, `azure.signinlogs.properties.session_id`, `source.ip`, and `azure.signinlogs.properties.resource_display_name`.
*   Implement conditional access policies to restrict device code flows to trusted networks and devices, mitigating the risk of AiTM attacks (reference: Microsoft documentation on conditional access).
*   Revoke refresh tokens for any compromised users and reset their credentials per policy, as mentioned in the investigation steps.
