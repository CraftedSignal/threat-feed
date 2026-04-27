---
title: Large-Scale OAuth Device Code Phishing Campaign Observed in April 2026
slug: 2026-05-oauth-device-code-phishing
description: In early April 2026, Arctic Wolf tracked a large-scale device code phishing campaign across multiple regions and sectors where threat actors abused OAuth device code flow to trick victims into providing authentication codes.
date: "2026-04-24T19:52:35Z"
severities:
  - high
tags:
  - oauth
  - device-code
  - phishing
  - initial-access
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://arcticwolf.com/resources/blog/token-bingo-dont-let-your-code-be-the-winner/
rules:
  - title: Detect Suspicious Azure AD Application Registration
    description: Detects the creation of new Azure AD applications with suspicious permissions or settings often used in OAuth phishing attacks.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - configuration
      - o365
  - title: Detect High Volume of Device Code Flow Requests
    description: Detects a high number of device code flow requests originating from a single IP address, which may indicate a phishing campaign.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - authentication
      - azuread
rules_count: 2
---

In early April 2026, Arctic Wolf observed a widespread phishing campaign that abused the OAuth device code flow. This campaign targeted organizations across multiple regions and sectors, mirroring the "Riding the Rails" campaign observed by Huntress in late March. The attackers exploited the device code grant type in the OAuth 2.0 authorization framework to obtain access tokens. By tricking users into entering a code on a legitimate Microsoft login page, attackers bypassed traditional MFA…
