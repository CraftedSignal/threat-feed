---
title: Tycoon2FA Phishing-as-a-Service Platform Resurgence After Takedown
slug: 2026-03-tycoon2fa-resurgence
description: The Tycoon2FA PhaaS platform, used to bypass MFA and compromise email accounts, has demonstrated resilience following a takedown attempt, with cloud compromise activity returning to pre-disruption levels and actors maintaining previously observed tactics.
date: "2026-03-28T09:27:11Z"
severities:
  - high
tags:
  - phishing
  - credential-theft
  - mfa-bypass
  - cloud
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
  - title: Detect Tycoon2FA PhaaS Redirection
    description: Detects potential phishing attempts redirecting to Tycoon2FA infrastructure by identifying redirects to suspicious domains mimicking legitimate login pages.
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
  - title: Detect Tycoon2FA PhaaS Cookie Theft
    description: Detects potential cookie theft attempts by identifying network connections originating from uncommon processes accessing common credential URLs, indicative of session hijacking.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On March 4, 2026, Europol announced the technical disruption of Tycoon2FA, a subscription-based phishing-as-a-service (PhaaS) platform used by cybercriminals to bypass multifactor authentication (MFA) and compromise email accounts. The takedown involved seizing 330 domains that formed the platform's core infrastructure. Despite this disruption, CrowdStrike Falcon Complete Next-Gen MDR team observed a short-term decrease followed by a return to pre-disruption levels of cloud compromises. The…
