---
title: Device Code Phishing Exploiting OAuth 2.0 Device Authorization Grant Flow
slug: 2026-05-device-code-phishing
description: Threat actors are increasingly using device code phishing, often via Phishing-as-a-Service platforms, to compromise user accounts by abusing the OAuth 2.0 device authorization grant flow and capturing authentication tokens, enabling account takeover, data theft, and business email compromise.
date: "2026-05-14T09:02:04Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - TA4903
tags:
  - device-code-phishing
  - phishing
  - credential-theft
  - oAuth
vendors:
  - Microsoft
  - Adobe
  - DocuSign
  - Cloudflare
products:
  - Microsoft 365
  - microsoft.com
  - DocuSign
  - Adobe
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1133
    technique_name: External Remote Services
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://www.proofpoint.com/us/blog/threat-insight/device-code-phishing-evolution-identity-takeover
rules:
  - title: Detect Device Code Phishing Landing Page Redirection via Cloudflare Workers
    description: Detects device code phishing attempts where the initial link redirects through a Cloudflare Workers URL before landing on a fake login page.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - webserver
  - title: Detect Microsoft Device Login Page Access After Redirection
    description: Detects access to the legitimate Microsoft device login page (microsoft.com/devicelogin) after a redirection, which may indicate a device code phishing attempt.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
rules_count: 2
---

Device code phishing is a growing threat where attackers abuse the OAuth 2.0 device authorization grant flow to compromise user accounts, particularly Microsoft 365. This technique has surged in popularity following the release of criminal device code phishing tools in fall 2025, coupled with the rise of "vibe coding" and Phishing-as-a-Service (PhaaS) platforms like EvilTokens and Tycoon. Campaigns typically begin with an email containing a URL or QR code. When a user clicks the link or scans the code, they are directed to a fake landing page impersonating a legitimate service like Microsoft or DocuSign, prompting them to enter a device code. By entering this code into the legitimate Microsoft device code authentication portal, the user inadvertently grants the attacker access to their account, leading to potential data theft, fraud, and business email compromise. TA4903 is one actor using device code phishing almost exclusively to steal credentials.

## Attack Chain

1.  Initial phishing email is sent, containing a URL or QR code. The email may contain a lure such as a salary notification or a document requiring a signature. Some campaigns even use blank email bodies.
2.  The user clicks the URL or scans the QR code, redirecting them to a landing page. This redirect may occur via Cloudflare Workers URLs.
3.  The landing page impersonates a legitimate service, such as Microsoft or DocuSign, and prompts the user to enter a device code. Some kits like ARTokens require the user to enter their email address first.
4.  The user is instructed to go to the legitimate Microsoft device login portal (https[:]//microsoft[.]com/devicelogin) and enter the provided code.
5.  The user enters the device code, unwittingly granting the attacker's malicious application access to their account.
6.  The attacker captures authentication tokens.
7.  The attacker uses the captured tokens to access the user's account, including data and other services the account has access to.
8.  The attacker performs actions such as stealing sensitive information, conducting business email compromise, or moving laterally within the compromised environment.

## Impact

Successful device code phishing attacks can result in full account takeover, giving attackers access to sensitive information and enabling business email compromise. Attackers can use compromised accounts to send further phishing emails, widening the scope of the attack. Some PhaaS platforms like EvilTokens even offer tools to automate the management of multiple compromised accounts. The ultimate impact can include financial loss, data breaches, and reputational damage for targeted organizations. The technique is observed in multiple languages targeting organizations globally.

## Recommendation

*   Implement policies to educate users about device code phishing and the legitimate Microsoft device login process.
*   Deploy the Sigma rule "Detect Device Code Phishing Landing Page Redirection via Cloudflare Workers" to identify potential phishing attempts (see rule below).
*   Monitor network traffic for connections to the legitimate Microsoft device login portal (https[:]//microsoft[.]com/devicelogin) following a redirect from unusual or suspicious domains.
*   Implement conditional access policies that restrict the use of device codes from untrusted networks or locations.
*   Block known PhaaS platforms and associated infrastructure used for device code phishing, such as those associated with EvilTokens.
*   Monitor email traffic for unusual patterns, such as emails with blank bodies containing URLs or QR codes, as observed in some campaigns by TA4903.
