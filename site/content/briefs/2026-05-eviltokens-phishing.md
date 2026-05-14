---
title: EvilTokens PhaaS Platform Leverages AI for Device Code Phishing Attacks
slug: 2026-05-eviltokens-phishing
description: The EvilTokens phishing-as-a-service (PhaaS) platform sold on Telegram is capable of launching device code phishing attacks at scale, leveraging AI to generate convincing and personalized lures, enabling aspiring cybercriminals to bypass traditional security measures, including MFA.
date: "2026-05-14T21:01:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - device code phishing
  - AI
  - Telegram
vendors:
  - Microsoft
  - Cisco
  - Trend Micro
  - Mimecast
  - Railway
  - DocuSign
products:
  - Microsoft 365
  - Microsoft Forms
  - Cisco email security
  - Trend Micro email security
  - Mimecast email security
  - Railway Platform-as-a-Service
  - DocuSign
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
  - https://www.huntress.com/blog/device-code-phishing-ai-mfa-bypass
iocs:
  - type: domain
    value: docusign.com
  - type: domain
    value: microsoft.com
ioc_counts:
  domain: 2
rules:
  - title: Detect Device Code Phishing via Railway Infrastructure
    description: Detects suspicious login events originating from Railway infrastructure, potentially indicating EvilTokens device code phishing activity.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1189
    data_sources:
      - network_connection
      - windows
  - title: Detect High Volume of Authentication Failures followed by Success from Same IP
    description: Detects a high volume of authentication failures followed by a successful login from the same IP address within a short time frame, which could indicate an attacker attempting to brute-force credentials or bypass MFA using stolen session tokens from device code phishing.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1189
    data_sources:
      - authentication
      - o365
rules_count: 2
---

The EvilTokens platform represents a shift in the phishing landscape by offering phishing-as-a-service (PhaaS) on Telegram. This platform allows individuals with limited technical skills to conduct sophisticated device code phishing attacks. Sold for $1,500 plus a $500 maintenance fee, EvilTokens provides AI-generated lures, dynamic code generation, and post-compromise automation. The platform was used in a 16-day campaign starting on March 2, 2026, affecting 344 organizations across five countries. EvilTokens exploits a legitimate Microsoft authentication flow, making it difficult to detect with traditional security measures. The platform also leverages Railway, a legitimate Platform-as-a-Service (PaaS).

## Attack Chain

1.  Attacker purchases access to the EvilTokens PhaaS platform on Telegram for $1,500 + $500 maintenance.
2.  Attacker uses EvilTokens to initiate a device code authentication process against a target service (e.g., Microsoft 365).
3.  EvilTokens generates a personalized phishing email using AI, mimicking legitimate requests for construction bid proposals, DocuSign documents, or Microsoft Forms.
4.  The phishing email is sent to the victim, containing a link to a legitimate Microsoft page prompting for a device code.
5.  The victim clicks the link and enters the provided code, unwittingly authorizing the attacker's session.
6.  EvilTokens captures the valid session token through its backend infrastructure, relayed through Railway.
7.  The attacker uses the captured session token to gain unauthorized access to the victim's account.
8.  After gaining access, EvilTokens can draft convincing wire fraud emails in the victim's voice.

## Impact

The EvilTokens campaign impacted 344 organizations across five countries in a 16-day period. Successful attacks result in unauthorized access to accounts, potentially leading to data theft, business email compromise, and financial fraud. The use of AI in generating personalized lures increases the likelihood of successful phishing attempts. Traditional email security solutions such as Cisco, Trend Micro, and Mimecast were unable to detect the attacks, as the emails and URLs appeared legitimate.

## Recommendation

*   Monitor Microsoft 365 login events for unusual activity, such as logins originating from Railway infrastructure IPs, to detect potential EvilTokens attacks.
*   Implement user awareness training to educate employees about device code phishing and the risks of entering codes from unsolicited emails.
*   Deploy the Sigma rule "Detect Device Code Phishing via Railway Infrastructure" to identify suspicious login activity associated with the Railway PaaS.
*   Block access to known EvilTokens infrastructure, if any are identified, at the network level.
*   Monitor for unusual authentication flows or patterns that deviate from typical user behavior, especially those involving device code authentication.
