---
title: Azure AD Device Code Phishing Attack Detection
slug: 2024-01-03-azure-ad-device-code-phishing
description: This brief details the detection of Azure AD Device Code Phishing attacks, where attackers bypass MFA and Conditional Access Policies (CAPs) to gain unauthorized access to Azure AD resources by abusing the device code authentication protocol.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azuread
  - devicecode
  - phishing
  - accounttakeover
  - credentialaccess
vendors:
  - Microsoft
products:
  - Azure Active Directory
  - Exchange
  - Outlook Web Application
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal User-Controlled Hardware
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://attack.mitre.org/techniques/T1528
  - https://github.com/rvrsh3ll/TokenTactics
  - https://embracethered.com/blog/posts/2022/device-code-phishing/
  - https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html
  - https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
rules:
  - title: Azure AD Device Code Authentication Activity
    description: Detects Azure AD Device Code Authentication requests, which may indicate a phishing attack.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1528
      - T1566.002
    data_sources:
      - network_connection
      - azure
  - title: Azure AD Device Code Authentication by Unusual User Agent
    description: Detects Azure AD Device Code Authentication requests from unusual user agents, potentially indicating attacker activity.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1528
      - T1566.002
    data_sources:
      - network_connection
      - azure
rules_count: 2
---

Attackers are increasingly using Device Code Phishing to bypass Multi-Factor Authentication (MFA) and Conditional Access Policies in Azure Active Directory. This technique involves tricking users into entering a device code on a fake Microsoft login page, granting the attacker access to their accounts. This attack leverages the legitimate device code authentication flow, making it harder to detect than traditional phishing attacks. Successful device code phishing can lead to account takeover, data breaches, and unauthorized access to sensitive resources within the Azure AD environment, including Exchange mailboxes and Outlook Web Application (OWA). Defenders need to monitor for unusual device code authentication activity to mitigate the risk of these attacks. The technique abuses the OAuth 2.0 device authorization grant flow, designed for devices without a browser.

## Attack Chain

1.  The attacker sends a phishing email to the target user. This email contains a link to a fake Microsoft login page.
2.  The user clicks the link and is prompted to enter a code. The attacker initiates a device code authentication flow on a compromised or attacker-controlled device.
3.  The attacker obtains a device code and presents it to the victim through the phishing page.
4.  The user enters the device code on the fake Microsoft login page, unknowingly authorizing the attacker's device.
5.  The attacker's device requests an access token from Azure AD using the device code.
6.  Azure AD validates the device code and, if valid, prompts the user (via the legitimate Microsoft authentication flow, but on the attacker's device) to authenticate and grant permissions.
7.  The user authenticates and grants the requested permissions, completing the device code authentication flow on the attacker's device.
8.  The attacker obtains an access token and can now access the user's Azure AD resources, such as Exchange mailboxes and OWA, without needing to bypass MFA on their primary device.

## Impact

Successful Azure AD device code phishing attacks can result in account takeovers, data breaches, and unauthorized access to sensitive resources. Attackers can gain access to Exchange mailboxes, Outlook Web Application (OWA), and other Azure AD-protected applications. The impact can range from data exfiltration and business email compromise to lateral movement within the Azure environment. This can lead to significant financial losses, reputational damage, and compliance violations. The number of victims and sectors targeted can vary, but the potential for widespread impact is high, especially in organizations with weak security awareness training.

## Recommendation

*   Deploy the Sigma rule `Azure AD Device Code Authentication Activity` to detect suspicious device code authentication requests in Azure AD SignInLogs.
*   Implement enhanced security awareness training to educate users about device code phishing attacks and how to identify fake login pages.
*   Monitor Azure AD SignInLogs for unusual authentication patterns, such as device code authentications from unfamiliar locations or devices.
*   Configure Conditional Access Policies to restrict device code authentication to trusted devices and locations.
*   Review and harden Conditional Access Policies to prevent bypasses via device code authentication, referencing the Microsoft documentation on device code flows: https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
*   Enable logging of Azure AD sign-in events and ensure that logs are ingested into a SIEM or security analytics platform for analysis.
