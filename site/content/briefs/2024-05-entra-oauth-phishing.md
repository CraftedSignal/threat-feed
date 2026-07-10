---
title: Entra ID OAuth Phishing via Auth Broker to DRS
slug: 2024-05-entra-oauth-phishing
description: Detection of OAuth phishing in Microsoft Entra ID through Microsoft Authentication Broker (MAB) and Device Registration Service (DRS) indicated by the same user principal and session ID originating from multiple IP addresses within a short timeframe, indicative of unauthorized token acquisition.
date: "2024-05-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - entra-id
  - oauth-phishing
  - initial-access
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
  - Microsoft Authentication Broker
  - Device Registration Service
  - Microsoft 365
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/
  - https://github.com/dirkjanm/ROADtools
  - https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/
iocs:
  - type: url
    value: https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/
  - type: domain
    value: dirkjanm.io
ioc_counts:
  domain: 1
  url: 1
rules:
  - title: Entra ID OAuth Flow from Multiple IPs
    description: Detects OAuth authorization flows in Microsoft Entra ID where the same user principal and session ID are observed across multiple IP addresses, indicating potential OAuth phishing activity.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - network_connection
      - azure
  - title: Entra ID OAuth Flow from Multiple IPs - Network Connection
    description: Detects network connections associated with suspicious OAuth flows based on multiple IP addresses within a short timeframe.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - initial_access
    techniques:
      - T1566
    data_sources:
      - network_connection
      - azure
rules_count: 2
---

This threat involves attackers conducting OAuth phishing campaigns targeting Microsoft Entra ID users. The attackers craft legitimate Microsoft login URLs to trick users into authenticating, thereby obtaining authorization codes. These codes are then exchanged for access and refresh tokens, allowing the attackers to gain unauthorized access to the user's resources. The Microsoft Authentication Broker (MAB) is used as the client application, and the Device Registration Service (DRS) is the target resource. The activity is characterized by the same user principal and session ID being observed across multiple IP addresses within a 5-minute window. This activity was observed starting in early 2025. The scope of this threat includes any organization utilizing Microsoft Entra ID and the MAB for device registration.

## Attack Chain

1.  The attacker crafts a phishing email containing a malicious link that leads to a fake Microsoft login page.
2.  The victim clicks the link and is prompted to enter their credentials, unknowingly providing them to the attacker.
3.  The attacker uses the stolen credentials to initiate an OAuth authorization flow via the Microsoft Authentication Broker (MAB) with the Device Registration Service (DRS) as the target.
4.  The legitimate Microsoft login page redirects the user and returns an authorization code to the attacker-controlled application.
5.  The attacker exchanges the authorization code for access and refresh tokens, gaining unauthorized access to the user's Entra ID resources.
6.  The attacker uses the access token to enumerate devices registered to the user via Microsoft Graph.
7.  The attacker uses the refresh token to maintain persistent access to the user's resources, even after the initial session expires.
8.  The attacker leverages access to DRS to potentially manipulate device registrations and further compromise the environment.

## Impact

Successful OAuth phishing can lead to unauthorized access to sensitive data and resources within the targeted organization. An attacker with valid access and refresh tokens can impersonate the user, potentially leading to data exfiltration, privilege escalation, and lateral movement within the network. Organizations utilizing Microsoft Entra ID are susceptible, with observed campaigns targeting Microsoft 365 OAuth workflows as reported by Volexity in April 2025.

## Recommendation

*   Enable and configure the Microsoft Entra ID Sign-In Logs integration to collect sign-in logs, as the detection rule relies on this data source (rule configuration).
*   Deploy the provided Sigma rule to your SIEM to detect suspicious OAuth flows involving MAB and DRS based on multiple IP addresses (rule: "Entra ID OAuth Flow from Multiple IPs").
*   Review Conditional Access policies for the Microsoft Authentication Broker (app ID: `29d9ed98-a469-4536-ade2-f981bc1d605e`) to enforce MFA and device trust (reference: note section in rule definition).
*   Monitor network connections for anomalous traffic originating from IPs associated with suspicious OAuth flows (rule: "Entra ID OAuth Flow from Multiple IPs - Network Connection").
*   Block access to known phishing domains and URLs used in OAuth phishing campaigns to prevent initial access (IOC: `https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/`).
