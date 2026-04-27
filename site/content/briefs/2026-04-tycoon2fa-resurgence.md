---
title: Tycoon2FA Phishing-as-a-Service Platform Resurgence
slug: 2026-04-tycoon2fa-resurgence
description: The Tycoon2FA Phishing-as-a-Service platform, used to bypass MFA and compromise email accounts, has demonstrated resilience following a law enforcement takedown, with campaign activity returning to pre-disruption levels and TTPs remaining consistent.
date: "2026-03-30T06:20:50Z"
severities:
  - high
tags:
  - phishing
  - credential-theft
  - phishing-as-a-service
  - cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://www.crowdstrike.com/en-us/blog/tycoon2fa-phishing-as-a-service-platform-persists-following-takedown/
rules:
  - title: Detect Tycoon2FA Phishing Landing Page Redirection
    description: Detects redirects to potential Tycoon2FA phishing landing pages by monitoring network connections for specific domain patterns after an initial HTTP request.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Tycoon2FA competitor domain RaccoonO365
    description: Detects redirects to potential RaccoonO365 phishing landing pages by monitoring network connections for specific domain patterns after an initial HTTP request.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On March 4, 2026, Europol disrupted Tycoon2FA, a Phishing-as-a-Service (PhaaS) platform enabling cybercriminals to bypass multifactor authentication (MFA). This takedown involved seizing 330 domains that constituted the platform’s core infrastructure. Despite this disruption, CrowdStrike Falcon Complete Next-Gen MDR and Counter Adversary Operations teams have observed a resurgence in Tycoon2FA campaign activity. While there was a short-term decrease in activity immediately following the…
