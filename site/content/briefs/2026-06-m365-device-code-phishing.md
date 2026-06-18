---
title: M365 Identity Device Code Grant with Unusual User and ASN
slug: 2026-06-m365-device-code-phishing
description: Threat actors leveraging phishing kits such as Kali365 and associated with groups like Storm-2372 are conducting device code phishing campaigns against Microsoft 365 users to steal MFA-satisfied authentication tokens by tricking victims into completing legitimate OAuth device code grants from attacker-controlled residential proxy or hosting infrastructure, leading to unauthorized account access and potential data exfiltration.
date: "2026-06-18T15:35:08Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Storm-2372
tags:
  - cloud
  - saas
  - identity
  - phishing
  - mfa-bypass
  - office365
vendors:
  - Microsoft
products:
  - Microsoft 365
  - Microsoft Authentication Broker
  - Microsoft Graph
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://arcticwolf.com/resources/blog/token-bingo-dont-let-your-code-be-the-winner/
  - https://arcticwolf.com/resources/blog/kali365-expands-into-aws-microsoft-okta-xerox-max-messenger/
  - https://www.ic3.gov/PSA/2026/PSA260521
  - https://www.volexity.com/blog/2025/02/13/multiple-russian-threat-actors-targeting-microsoft-device-code-authentication/
  - https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/
iocs:
  - type: string
    value: 29d9ed98-a469-4536-ade2-f981bc1d605e
  - type: string
    value: 00000003-0000-0000-c000-000000000000
ioc_counts:
  string: 2
rules:
  - title: M365 Device Code Grant to Microsoft Graph (Baseline)
    description: Detects a Microsoft 365 OAuth device code grant event for the Microsoft Authentication Broker and Microsoft Graph, a prerequisite for device code phishing attacks. This rule serves as a baseline for monitoring this specific authentication flow.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1550.001
      - T1566.002
    data_sources:
      - network_connection
      - o365
  - title: M365 Device Code Grant from Suspicious ASN
    description: Detects Microsoft 365 OAuth device code grant activity (`Cmsi:Cmsi`) for the Microsoft Authentication Broker and Microsoft Graph originating from IP addresses associated with common hosting, VPN, or datacenter Autonomous System Numbers (ASNs). This pattern is highly suspicious for interactive user authentication and indicative of device code phishing.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1550.001
      - T1566.002
    data_sources:
      - network_connection
      - o365
  - title: Azure AD Device Registration for Suspicious Context
    description: Detects 'Add registered device' events in Azure AD audit logs, which can indicate an attacker establishing Primary Refresh Token (PRT) persistence after gaining initial access through methods like device code phishing.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1078.004
      - T1136.002
    data_sources:
      - network_connection
      - azure
rules_count: 3
---

Threat actors, notably utilizing sophisticated phishing kits like Kali365 and associated with groups such as Storm-2372, are actively exploiting the OAuth device code grant flow in Microsoft 365 environments. This technique, highlighted in a recent IC3 PSA and by vendors like Arctic Wolf, Volexity, and Microsoft, circumvents traditional Multi-Factor Authentication (MFA) by prompting users to authenticate against genuine Microsoft endpoints (microsoft.com/devicelogin). The attacker's server-side component then polls the token endpoint from an unusual Autonomous System Number (ASN)—typically a residential proxy, VPN, or hosting provider—to redeem the resulting MFA-satisfied token. This means the authentication event (identified by `Cmsi:Cmsi` for the Microsoft Authentication Broker with application ID `29d9ed98-a469-4536-ade2-f981bc1d605e` targeting Microsoft Graph with ID `00000003-0000-0000-c000-000000000000`) originates from an unexpected network location for the user, signaling compromise and enabling persistent unauthorized access to cloud resources.

## Attack Chain

1.  **Initial Access**: Threat actors send spearphishing messages, often impersonating trusted entities, containing malicious links that prompt recipients to use a "device code" for authentication.
2.  **Device Code Initiation**: The victim interacts with the phishing link, which initiates a legitimate OAuth device code flow and displays a unique, short-lived code on a malicious or compromised web page.
3.  **Legitimate Authentication**: The victim is directed to a genuine Microsoft device login portal (e.g., `microsoft.com/devicelogin`), where they are instructed to enter the provided device code and then complete multi-factor authentication (MFA).
4.  **Token Harvesting**: Concurrently, the attacker's server-side component (e.g., Kali365 phishing kit), operating from a suspicious Autonomous System Number (ASN) like a residential proxy or cloud hosting provider, continuously polls Microsoft to redeem the device code for an OAuth token.
5.  **Unauthorized Token Use**: The attacker successfully obtains a valid, MFA-satisfied refresh token from the Microsoft token endpoint, granting them persistent, unauthorized access to the victim's Microsoft 365 account without needing to re-authenticate or bypass MFA.
6.  **Reconnaissance & Persistence**: The attacker utilizes the stolen token to perform actions such as querying the Microsoft Graph API (`00000003-0000-0000-c000-000000000000`) for user data (e.g., `/me` endpoint, mailbox enumeration) or registering new devices for the victim's account to establish Primary Refresh Token (PRT) persistence.
7.  **Impact**: The attacker proceeds with data exfiltration from services like Exchange Online or SharePoint, or gains access to sensitive organizational resources, leading to significant data breaches or further lateral movement within the cloud environment.

## Impact

Successful device code phishing campaigns result in full account takeover of Microsoft 365 user accounts, even those protected by MFA. This leads to immediate unauthorized access to sensitive corporate data within Exchange Online, SharePoint, Teams, and other Microsoft Graph-integrated services. Attackers can exfiltrate emails, documents, and other critical information, impersonate users for further phishing or business email compromise (BEC) attacks, and establish persistent access mechanisms like device registration to maintain long-term presence. The financial and reputational damage from such breaches can be substantial, affecting organizations across all sectors that rely on Microsoft 365.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM, focusing on detecting `o365.audit` events for device code grants and suspicious source ASNs.
*   Investigate all alerts generated by the "M365 Device Code Grant from Suspicious ASN" rule by reviewing `source.as.organization.name`, `source.ip`, and `source.geo.country_name` for consistency with the user's normal activity.
*   Enable comprehensive `o365.audit` logging, specifically for `ExtendedProperties.RequestType`, `ApplicationId`, `Target.ID`, `source.as.number`, and `source.as.organization.name` fields, to ensure the detection rules are effective.
*   Implement Conditional Access policies to restrict device code authentication (`29d9ed98-a469-4536-ade2-f981bc1d605e`) to only necessary users and applications or to trusted network locations.
*   Review and remove any unauthorized device registrations in Azure AD that may have resulted from post-exploitation activities detected by the "Azure AD Device Registration for Suspicious Context" rule.
*   Educate users on the risks of device code phishing and advise them against entering codes presented by unsolicited messages or documents.
