---
title: Tycoon2FA PhaaS Platform Resurgence After Takedown
slug: 2026-03-tycoon2fa-resurgence
description: The Tycoon2FA phishing-as-a-service (PhaaS) platform, disrupted in March 2026, has resurged with consistent tactics, employing adversary-in-the-middle (AITM) techniques to bypass MFA and compromise email accounts through phishing campaigns, credential theft, and session cookie hijacking.
date: "2026-03-28T08:28:28Z"
severities:
  - high
tags:
  - phishing
  - credential-theft
  - MFA-bypass
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
  - https://www.crowdstrike.com/en-us/blog/tycoon2fa-phishing-as-a-service-platform-persists-following-takedown/
ioc_counts:
  email: 1
rules:
  - title: Detect Email Address Extraction via JavaScript
    description: Detects JavaScript code attempting to extract email addresses from web pages, a technique used by Tycoon2FA.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Fake Microsoft 365 Login Page
    description: Detects access to fake Microsoft 365 login pages hosted on suspicious domains.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1566.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Tycoon2FA is a subscription-based PhaaS platform that enables cybercriminals to bypass multifactor authentication (MFA) and compromise email accounts using adversary-in-the-middle (AITM) techniques. The platform gained prominence in 2025, reportedly generating over 30 million malicious emails in a single month and accounting for 62% of all phishing attempts blocked by Microsoft at one point. On March 4, 2026, Europol announced a technical disruption of Tycoon2FA, seizing 330 domains forming the…
