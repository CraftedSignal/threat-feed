---
title: Tycoon2FA Phishing-as-a-Service Platform Resurgence
slug: 2026-04-tycoon2fa-resurgence
description: The Tycoon2FA Phishing-as-a-Service (PhaaS) platform, disrupted in March 2026, has resurged with cloud compromise active remediations returning to early 2026 levels, continuing to bypass MFA and compromise email accounts through phishing campaigns.
date: "2026-03-29T06:44:52Z"
severities:
  - high
tags:
  - phishing
  - credential-theft
  - mfa-bypass
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
rules:
  - title: Detect Tycoon2FA Fake Login Page Redirection
    description: Detects redirections to fake Microsoft 365 or Google login pages hosted on suspicious domains.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1566
    data_sources:
      - network_connection
      - windows
  - title: Detect Tycoon2FA Cookie Theft via CAPTCHA
    description: Detects suspicious network connections following interaction with a CAPTCHA page, indicating potential cookie theft.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Tycoon2FA is a subscription-based Phishing-as-a-Service (PhaaS) platform that enables cybercriminals to bypass multifactor authentication (MFA) and compromise email accounts. The platform was disrupted on March 4, 2026, by Europol and law enforcement in six countries, seizing 330 domains. Before the takedown, in mid-2025, the platform was responsible for 62% of all phishing attempts blocked by Microsoft, generating over 30 million malicious emails in a single month. Despite the disruption…
