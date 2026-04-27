---
title: Tycoon2FA Phishing-as-a-Service Platform Resurgence
slug: 2026-04-tycoon2fa-resurgence
description: The Tycoon2FA Phishing-as-a-Service (PhaaS) platform, used to bypass MFA and compromise email accounts, has rebounded after a law enforcement takedown, with campaign activity and tactics returning to pre-disruption levels.
date: "2026-03-31T01:45:17Z"
severities:
  - high
tags:
  - phishing
  - credential-theft
  - mfa-bypass
  - phaas
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
  - title: Detect Tycoon2FA Phishing Redirection
    description: Detects process creation events indicative of a user being redirected to a Tycoon2FA phishing page after clicking a link in a phishing email.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Tycoon2FA Cookie Theft via JavaScript
    description: Detects JavaScript files attempting to steal cookies, a technique used by Tycoon2FA to bypass MFA.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Tycoon2FA is a subscription-based Phishing-as-a-Service (PhaaS) platform that enables cybercriminals to bypass multifactor authentication (MFA) and compromise email accounts. On March 4, 2026, Europol announced a technical disruption of Tycoon2FA, seizing 330 domains that formed the platform's core infrastructure. Despite this takedown, CrowdStrike observed only a short-term decrease in Tycoon2FA campaign activity. The volume of cloud compromises has since increased to levels previously…
