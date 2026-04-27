---
title: Tycoon2FA Phishing-as-a-Service Platform Resurgence After Takedown
slug: 2026-04-tycoon2fa-resurgence
description: The Tycoon2FA phishing-as-a-service platform, which bypasses MFA, has resurged to pre-takedown activity levels, indicating continued risk despite law enforcement disruption efforts.
date: "2026-03-31T08:36:16Z"
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
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.crowdstrike.com/en-us/blog/tycoon2fa-phishing-as-a-service-platform-persists-following-takedown/
rules:
  - title: Detect Redirection to Tycoon2FA CAPTCHA Pages
    description: Detects potential phishing attempts redirecting users to Tycoon2FA CAPTCHA pages
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1566
      - T1566.001
    data_sources:
      - network_connection
      - windows
  - title: Detect JavaScript Email Address Extraction
    description: Detects suspicious JavaScript files attempting to extract email addresses
    platform: sigma
    severity: low
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1566
      - T1566.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Tycoon2FA is a subscription-based phishing-as-a-service (PhaaS) platform that allows cybercriminals to bypass multifactor authentication (MFA) and compromise email accounts. The platform began operations in 2023 and by mid-2025 was responsible for 62% of all phishing attempts blocked by Microsoft, generating over 30 million malicious emails in a single month. On March 4, 2026, Europol disrupted the platform by seizing 330 domains. Despite this takedown, CrowdStrike Falcon Complete observed a…
