---
title: Tycoon2FA PhaaS Platform Resurgence Following Takedown
slug: 2026-04-tycoon2fa-resurgence
description: The Tycoon2FA phishing-as-a-service (PhaaS) platform, disrupted by law enforcement on March 4, 2026, has shown a resurgence in activity, enabling cybercriminals to bypass MFA and compromise email accounts using adversary-in-the-middle (AITM) techniques.
date: "2026-03-30T06:31:25Z"
severities:
  - high
tags:
  - phishing
  - mfa-bypass
  - aitm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1005
    technique_name: Data from Local System
references:
  - https://www.crowdstrike.com/en-us/blog/tycoon2fa-phishing-as-a-service-platform-persists-following-takedown/
rules:
  - title: Detect Redirection to Fake CAPTCHA Pages
    description: Detects redirection to potentially malicious CAPTCHA pages, which may indicate a phishing attack using Tycoon2FA.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious JavaScript for Email Extraction
    description: Detects JavaScript files being served that are used for extracting email addresses, a common technique in Tycoon2FA attacks.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1005
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Tycoon2FA Phishing-as-a-Service (PhaaS) platform, which was subject to a coordinated takedown by Europol and law enforcement agencies on March 4, 2026, has demonstrated a resurgence in malicious activity. Tycoon2FA, operating since 2023, provides a subscription-based service enabling cybercriminals to bypass multifactor authentication (MFA) and compromise email accounts through adversary-in-the-middle (AITM) techniques. The takedown resulted in the seizure of 330 domains associated with the…
