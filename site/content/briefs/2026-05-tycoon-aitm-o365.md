---
title: Microsoft 365 AiTM UserLoggedIn via Office App (Tycoon2FA)
slug: 2026-05-tycoon-aitm-o365
description: This rule detects Microsoft 365 audit events indicative of Tycoon 2FA phishing-as-a-service (PhaaS) adversary-in-the-middle (AiTM) activity, identifying UserLoggedIn events where the Microsoft Authentication Broker requests access to Microsoft Graph or Exchange Online, or the Office web client application authenticates to itself, combined with Node.js-style user agents, bypassing MFA by relaying authentication and capturing session material.
date: "2026-05-18T09:26:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - identity
  - saas
  - microsoft365
  - aitm
  - tycoon2fa
  - phishing
vendors:
  - Microsoft
products:
  - Microsoft 365
  - Microsoft Graph
  - Exchange Online
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
references:
  - https://any.run/malware-trends/tycoon/
rules:
  - title: Detect Suspicious Node.js User Agent with Microsoft Authentication Broker
    description: Detects Microsoft Authentication Broker requesting access to Microsoft Graph or Exchange Online with Node.js-style user agents (node, axios, undici), indicative of Tycoon2FA AiTM phishing.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1539
      - T1566
    data_sources:
      - authentication
      - o365
  - title: Detect Self-Authenticating Office Web Client with Suspicious User Agent
    description: Detects Office web client authenticating to itself with Node.js-style user agents, characteristic of Tycoon2FA AiTM attacks.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1539
      - T1566
    data_sources:
      - authentication
      - o365
rules_count: 2
---

This detection focuses on identifying adversary-in-the-middle (AiTM) phishing activity targeting Microsoft 365 environments, specifically related to the Tycoon 2FA phishing-as-a-service platform. The attack leverages AiTM techniques to bypass multi-factor authentication (MFA) by relaying authentication requests and capturing session cookies. The detection is based on the observation of specific Microsoft 365 audit events, namely "UserLoggedIn", combined with anomalous user agent strings indicative of Node.js-based tooling (node, axios, undici). The activity involves the Microsoft Authentication Broker requesting access to Microsoft Graph or Exchange Online, or the Office web client authenticating to itself, which are patterns associated with Tycoon 2FA. Defenders should baseline legitimate automation and developer tooling environments to avoid false positives.

## Attack Chain

1.  The attacker initiates a phishing campaign targeting Microsoft 365 users to steal credentials and bypass MFA.
2.  The victim receives a phishing email or message containing a link to a malicious proxy site that spoofs a legitimate Microsoft 365 login page.
3.  The victim clicks on the link and enters their credentials into the fake login page.
4.  The attacker's proxy site relays the credentials to the real Microsoft 365 login page.
5.  The real Microsoft 365 login page sends an MFA request to the victim.
6.  The attacker's proxy site relays the MFA request to the victim and captures the MFA code.
7.  The attacker's proxy site relays the MFA code to the real Microsoft 365 login page, completing the authentication process.
8.  The attacker captures the session cookie, allowing them to access the victim's Microsoft 365 account without needing the credentials or MFA code again.

## Impact

Successful exploitation allows attackers to gain unauthorized access to Microsoft 365 accounts, potentially leading to data exfiltration, financial fraud, or further lateral movement within the organization. The use of Tycoon 2FA underscores the increasing sophistication of phishing attacks, making it more difficult for users to detect and avoid. Without proper detection and response mechanisms, organizations are vulnerable to significant compromise.

## Recommendation

*   Deploy the Sigma rule "M365 Potential AiTM UserLoggedIn via Office App (Tycoon2FA)" to your SIEM and tune for your environment to detect suspicious login patterns.
*   Review `o365.audit.UserId`, `user_agent.original`, `source.ip` or `o365.audit.ActorIpAddress`, and related Entra ID sign-in logs (`azure.signinlogs`) for the same session or time window as described in the rule's "Triage and Analysis" section.
*   Revoke refresh tokens for compromised users, reset credentials per policy, and review conditional access outcomes if malicious activity is confirmed, as outlined in the rule's "Response and Remediation" section.
*   Block or monitor the source IPs identified in the logs and escalate per incident procedures, as suggested in the rule's "Response and Remediation" section.
