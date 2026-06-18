---
title: Microsoft 365 OAuth Device Code Phishing Exploits Non-Compliant Devices
slug: 2026-06-m365-device-code-phishing
description: Attackers are actively exploiting the OAuth device code flow in Microsoft 365 to bypass multi-factor authentication (MFA) and gain initial access, leveraging phishing kits like Kali365 and tradecraft similar to Storm-2372 to harvest MFA-satisfied tokens from non-compliant or attacker-controlled devices, and subsequently establishing persistence through device registration.
date: "2026-06-18T15:37:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - saas
  - identity
  - microsoft-365
  - initial-access
  - phishing
  - persistence
vendors:
  - Microsoft
products:
  - Microsoft 365
  - Microsoft Entra ID
  - Exchange Online
  - SharePoint Online
  - Microsoft Teams
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://arcticwolf.com/resources/blog/token-bingo-dont-let-your-code-be-the-winner/
  - https://arcticwolf.com/resources/blog/kali365-expands-into-aws-microsoft-okta-xerox-max-messenger/
  - https://www.ic3.gov/PSA/2026/PSA260521
  - https://www.volexity.com/blog/2025/02/13/multiple-russian-threat-actors-targeting-microsoft-device-code-authentication/
  - https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/
rules:
  - title: M365 OAuth Device Code Grant from Non-Compliant Device
    description: Detects a Microsoft 365 user completing an OAuth device code grant ('Cmsi:Cmsi') from a device reported as non-compliant. This activity is a strong indicator of device code phishing, where attackers bypass MFA by having victims authenticate through genuine Microsoft endpoints on attacker-controlled or personal devices to harvest MFA-satisfied tokens.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1078
      - T1078.004
      - T1550
      - T1550.001
      - T1566
      - T1566.002
    data_sources:
      - cloud
      - o365
  - title: M365 Suspicious Device Registration by User
    description: Detects suspicious user-initiated device registration events in Microsoft 365, which threat actors commonly use after gaining initial access (e.g., via device code phishing) to establish Primary Refresh Token (PRT) persistence and maintain long-term access.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1098
      - T1098.001
    data_sources:
      - cloud
      - azure
rules_count: 2
---

Threat actors are increasingly utilizing sophisticated phishing techniques, specifically targeting the OAuth device code flow within Microsoft 365, to circumvent multi-factor authentication (MFA). Campaigns observed leveraging tools like Kali365 and tradecraft similar to Storm-2372, dating back at least to early 2025 according to referenced reports, lure victims into authorizing access on attacker-controlled or personal non-compliant devices. This method exploits the legitimate device code authentication mechanism by directing users to genuine Microsoft endpoints to complete their login and MFA, while the attacker's phishing kit polls the token endpoint in the background to harvest an MFA-satisfied access token. This approach bypasses traditional MFA protections by manipulating the authorization process itself, granting attackers persistent access and enabling subsequent malicious activities such as reconnaissance and data exfiltration.

## Attack Chain

1.  **Initial Access / Phishing Lure**: Attackers distribute phishing lures (e.g., email, instant message) containing a unique device code and instructions for the victim to visit a legitimate Microsoft verification URL (e.g., microsoft.com/devicelogin).
2.  **Device Code Entry**: The victim navigates to the genuine Microsoft verification URL and, as instructed by the lure, enters the attacker-provided device code.
3.  **Authentication and MFA**: The victim is prompted to authenticate with their Microsoft 365 credentials and completes multi-factor authentication (MFA) on a legitimate Microsoft login page.
4.  **Token Harvesting**: Concurrently, the attacker's phishing kit, having initiated the device code flow, continuously polls the token endpoint. Upon successful authentication and MFA by the victim, the kit intercepts and harvests the resulting MFA-satisfied refresh token and access token. This often occurs from a device not compliant with the organization's security policies.
5.  **Unauthorized Access**: The attacker uses the harvested tokens to gain unauthorized access to the victim's Microsoft 365 resources (e.g., Exchange Online, SharePoint Online, Microsoft Teams, OneDrive).
6.  **Persistence Establishment**: To maintain access, attackers may register a new device to the compromised user's account, establishing Primary Refresh Token (PRT) persistence that survives password changes.
7.  **Reconnaissance and Lateral Movement**: With persistent access, the attacker performs reconnaissance within the victim's environment, enumerating mailboxes, files, and other cloud resources, and potentially moving laterally to other connected applications or services.
8.  **Impact and Exfiltration**: Finally, the attacker may exfiltrate sensitive data, initiate further attacks, or manipulate cloud resources based on their objectives.

## Impact

Successful device code phishing attacks result in complete bypass of multi-factor authentication, granting attackers MFA-satisfied access tokens that provide persistent and unauthorized entry to critical Microsoft 365 services such as Exchange Online, SharePoint Online, and Teams. This leads to immediate compromise of user accounts, enabling data exfiltration, email account takeover, and access to sensitive documents. Attackers can also establish long-term persistence by registering new devices, making detection and remediation more challenging. While no specific victim counts or industry sectors are provided in the source, the technique is broadly applicable to any organization utilizing Microsoft 365, posing a significant risk of intellectual property theft, financial fraud, and business disruption.

## Recommendation

*   Deploy the Sigma rule "M365 OAuth Device Code Grant from Non-Compliant Device" to your SIEM to detect anomalous device code authentication originating from unmanaged endpoints.
*   Monitor `o365.audit` logs for `RequestType: "Cmsi:Cmsi"` events, paying close attention to `o365.audit.DeviceProperties` (especially `Value: "False"`) and the associated `source.ip` and `source.as.organization.name` for unusual origins.
*   Implement Conditional Access policies in Microsoft Entra ID to restrict device code authentication to only necessary users and applications, and enforce requirements for compliant or hybrid-joined devices.
*   Deploy the Sigma rule "M365 Suspicious Device Registration by User" to identify attempts by threat actors to establish persistence post-compromise by registering new devices.
*   Educate users about the risks of device code phishing, emphasizing vigilance against unsolicited requests to enter codes on authentication pages and the importance of verifying the authenticity of login prompts.
*   For confirmed compromises, immediately revoke all refresh tokens for the affected user, reset their credentials, and review `azure.signinlogs`, `azure.graphactivitylogs`, and `azure.auditlogs` for post-compromise activity and remove any unauthorized device registrations.
