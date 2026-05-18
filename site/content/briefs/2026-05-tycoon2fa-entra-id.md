---
title: Tycoon2FA AiTM Phishing via Microsoft Entra ID Sign-Ins
slug: 2026-05-tycoon2fa-entra-id
description: Detects Microsoft Entra ID sign-ins consistent with Tycoon2FA phishing-as-a-service (PhaaS) adversary-in-the-middle (AiTM) activity targeting Microsoft 365 and Gmail, where the Microsoft Authentication Broker requests tokens for Microsoft Graph or Exchange Online, or the Office web client application authenticates to itself, combined with Node.js-style user agents (node, axios, undici).
date: "2026-05-18T09:26:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - tycoon2fa
  - aitm
  - entra_id
  - phishing
  - credential_access
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
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
  - title: Entra ID Sign-in with Microsoft Auth Broker and Node.js User Agent (Tycoon2FA)
    description: Detects Microsoft Entra ID sign-ins using the Microsoft Authentication Broker requesting tokens for Microsoft Graph or Exchange Online with Node.js-style user agents, indicative of Tycoon2FA AiTM phishing.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1204.001
      - T1539
      - T1566
    data_sources:
      - authentication
      - azure
  - title: Entra ID Sign-in with Office Web Client and Node.js User Agent (Tycoon2FA)
    description: Detects Microsoft Entra ID sign-ins using the Office web client authenticating to itself with Node.js-style user agents, indicative of Tycoon2FA AiTM phishing.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1204.001
      - T1539
      - T1566
    data_sources:
      - authentication
      - azure
rules_count: 2
---

This rule detects Microsoft Entra ID sign-ins indicative of Tycoon2FA phishing-as-a-service (PhaaS) adversary-in-the-middle (AiTM) attacks. Tycoon2FA is designed to bypass multi-factor authentication (MFA) by relaying authentication requests and capturing session cookies, primarily targeting Microsoft 365 and Gmail accounts. The activity is characterized by the Microsoft Authentication Broker (app ID `29d9ed98-a469-4536-ade2-f981bc1d605e`) requesting tokens for Microsoft Graph (`00000003-0000-0000-c000-000000000000`) or Exchange Online (`00000002-0000-0ff1-ce00-000000000000`), or the Office web client application (app ID `4765445b-32c6-49b0-83e6-1d93765276ca`) authenticating to itself, in conjunction with Node.js-style user agents (node, axios, undici). Defenders should baseline legitimate automation and developer tooling using these patterns to minimize false positives.

## Attack Chain

1. The victim receives a phishing email or message designed to mimic a legitimate Microsoft 365 login page.
2. The victim clicks the link and is redirected to a Tycoon2FA-controlled server acting as a proxy.
3. The victim enters their credentials, which are captured by the Tycoon2FA proxy.
4. The Tycoon2FA proxy initiates a legitimate sign-in attempt to Microsoft Entra ID using the stolen credentials and relays the MFA request to the victim.
5. The victim completes MFA, and the Tycoon2FA proxy captures the session cookie.
6. The attacker uses the stolen session cookie to bypass MFA and gain access to the victim's Microsoft 365 account, impersonating the user.
7. The attacker leverages this access to perform actions such as reading emails, accessing files, or initiating further attacks.

## Impact

Successful exploitation leads to account compromise and unauthorized access to sensitive data within Microsoft 365 and Gmail environments. This can result in data breaches, financial loss, and reputational damage. Tycoon2FA is a phishing-as-a-service (PhaaS) platform, enabling even less sophisticated attackers to successfully bypass MFA, potentially affecting a large number of users.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect potential AiTM attacks targeting Microsoft Entra ID.
*   Monitor Microsoft Entra ID sign-in logs for the specific application IDs (`29d9ed98-a469-4536-ade2-f981bc1d605e`, `4765445b-32c6-49b0-83e6-1d93765276ca`) and resource IDs (`00000002-0000-0ff1-ce00-000000000000`, `00000003-0000-0000-c000-000000000000`) associated with Tycoon2FA, as described in the overview.
*   Investigate sign-ins originating from unusual user agents, especially those containing "node", "axios", or "undici" when used in conjunction with the Microsoft Authentication Broker or Office web client application.
*   Review conditional access policies and MFA configurations to ensure they are effectively preventing AiTM attacks.
*   Educate users about phishing techniques and the importance of verifying login pages and MFA requests.
