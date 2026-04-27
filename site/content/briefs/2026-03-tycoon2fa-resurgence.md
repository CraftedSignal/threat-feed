---
title: Tycoon2FA Phishing-as-a-Service Platform Resurgence After Takedown
slug: 2026-03-tycoon2fa-resurgence
description: The Tycoon2FA PhaaS platform, used for MFA bypass and email compromise, has demonstrated a resurgence in activity following a law enforcement takedown, indicating continued threat actor activity.
date: "2026-03-31T12:00:00Z"
severities:
  - high
tags:
  - phishing
  - credential-theft
  - mfa-bypass
  - phaas
  - tycoon2fa
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
  - title: Detect Tycoon2FA CAPTCHA Page Redirection
    description: Detects potential phishing attempts where users are redirected to a Tycoon2FA CAPTCHA page, indicating a possible credential harvesting attack.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Session Cookie Theft via JavaScript
    description: Detects potential session cookie theft attempts by identifying suspicious JavaScript execution that attempts to access or transmit cookie data.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Tycoon2FA platform is a subscription-based Phishing-as-a-Service (PhaaS) that enables cybercriminals to bypass multi-factor authentication (MFA) and compromise email accounts. First observed in 2023, the platform gained notoriety and in mid-2025 was reportedly responsible for 62% of all phishing attempts blocked by Microsoft, generating over 30 million malicious emails in a single month. On March 4, 2026, Europol announced a technical disruption, seizing 330 domains associated with the…
