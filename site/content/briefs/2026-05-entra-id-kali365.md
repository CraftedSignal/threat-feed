---
title: Entra ID Kali365 User-Agent Detected
slug: 2026-05-entra-id-kali365
description: This brief detects the use of the Kali365 user agent, a phishing-as-a-service platform, within Entra ID or Microsoft 365 logs, indicating potential account compromise through stolen tokens.
date: "2026-05-27T12:38:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - entra_id
  - o365
  - initial_access
  - credential_access
vendors:
  - Microsoft
products:
  - Entra ID
  - Microsoft 365
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://arcticwolf.com/resources/blog/token-bingo-dont-let-your-code-be-the-winner/
  - https://www.ic3.gov/PSA/2026/PSA260521
iocs:
  - type: ip
    value: 216.203.20.95
  - type: ip
    value: 162.243.166.119
  - type: ip
    value: 199.91.220.111
  - type: user-agent
    value: kali365-live/1.0.0
ioc_counts:
  ip: 3
  user-agent: 1
rules:
  - title: Entra ID Kali365 Default User-Agent Detected
    description: Detects the default user agent associated with the Kali365 phishing-as-a-service platform.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1528
      - T1566
    data_sources:
      - audit
      - o365
  - title: Entra ID Sign-in with Kali365 User-Agent
    description: Detects Entra ID sign-in events using the Kali365 default user-agent, indicative of stolen token usage.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1528
      - T1566
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The Kali365 (Kali365 Live) platform is a phishing-as-a-service (PhaaS) tool distributed via Telegram that automates OAuth 2.0 device code phishing and adversary-in-the-middle (AiTM) session capture against Microsoft 365 and Microsoft Entra ID. This platform provides affiliates with AI-generated lures, automated device code phishing campaigns, and OAuth token capture. The Kali365 Electron desktop client identifies itself with the user agent `kali365-live/1.0.0` when polling for and replaying captured OAuth tokens. Detection of this user agent in Entra ID sign-in logs, Entra ID audit logs, or the Microsoft 365 unified audit log indicates that an attacker-controlled Kali365 client is interacting with the tenant using stolen tokens. Given its nature as a criminal service with no legitimate enterprise use, this user agent serves as a high-fidelity indicator of active account compromise.

## Attack Chain

1.  The attacker gains initial access through phishing, sending a lure with a Microsoft device code.
2.  The victim enters the device code on a legitimate Microsoft verification page.
3.  The victim unknowingly authorizes the attacker's Kali365 application.
4.  Kali365 captures the resulting OAuth access and refresh tokens.
5.  The attacker uses the stolen OAuth tokens to access Microsoft 365 resources.
6.  The attacker uses the access to perform actions such as accessing mailboxes, creating inbox rules, or downloading files from OneDrive/SharePoint.
7.  The attacker maintains persistence via device registration in Entra ID.
8.  The attacker achieves persistent, MFA-free access to Microsoft 365 resources like Outlook, Teams, and OneDrive.

## Impact

A successful attack leveraging Kali365 can result in unauthorized access to sensitive data, compromised accounts, and persistent access to Microsoft 365 resources. The impact includes potential data exfiltration, business email compromise, and lateral movement within the organization. Given the criminal nature of the Kali365 service, affected organizations face significant reputational and financial risks. Successful exploitation allows attackers to bypass MFA and maintain persistent access, making detection and remediation critical.

## Recommendation

*   Deploy the "Entra ID Kali365 Default User-Agent Detected" rule to detect the Kali365 user agent in your environment.
*   Investigate any alerts triggered by the rule, focusing on the user and source IP involved, using the provided triage steps in the rule's note.
*   Block the Kali365 infrastructure IOCs (216.203.20.95, 162.243.166.119, 199.91.220.111) at your network perimeter.
*   Review and remove any rogue device registrations created by the user, as identified in the rule's note.
*   Apply Conditional Access policies to the device code grant to require managed/compliant devices.
