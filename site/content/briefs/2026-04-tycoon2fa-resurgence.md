---
title: Tycoon2FA Phishing-as-a-Service Resurgence After Takedown
slug: 2026-04-tycoon2fa-resurgence
description: The Tycoon2FA Phishing-as-a-Service platform, used to bypass multifactor authentication (MFA), has resurged to pre-takedown levels of activity following a disruption effort in March 2026, maintaining its original tactics, techniques, and procedures (TTPs) for credential harvesting and cloud compromise.
date: "2026-03-28T08:20:54Z"
severities:
  - high
tags:
  - phishing
  - credential-theft
  - MFA-bypass
  - phishing-as-a-service
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
ioc_counts:
  email: 1
rules:
  - title: Tycoon2FA Phishing Redirection
    description: Detects potential phishing attempts redirecting to Tycoon2FA infrastructure by identifying suspicious redirects to known CAPTCHA pages or fake login pages.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1566
      - T1566.001
    data_sources:
      - network_connection
      - windows
  - title: Tycoon2FA Cookie Theft via JavaScript
    description: Detects potential cookie theft attempts via malicious JavaScript files associated with Tycoon2FA campaigns.
    platform: sigma
    severity: medium
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

On March 4, 2026, Europol announced a technical disruption of the Tycoon2FA Phishing-as-a-Service (PhaaS) platform, which enabled cybercriminals to bypass multifactor authentication (MFA) and compromise email accounts. The takedown involved seizing 330 domains that formed the platform’s core infrastructure. However, following the takedown, CrowdStrike observed only a short-term decrease in Tycoon2FA campaign activity. The volume of cloud compromises has since returned to pre-disruption…
