---
title: Tycoon2FA Phishing-as-a-Service Resurgence After Takedown
slug: 2026-04-tycoon2fa-resurgence
description: The Tycoon2FA Phishing-as-a-Service (PhaaS) platform, which bypasses multi-factor authentication (MFA) using adversary-in-the-middle (AITM) techniques, has seen a resurgence in activity to pre-takedown levels despite a law enforcement disruption in March 2026.
date: "2026-03-28T11:00:46Z"
severities:
  - high
tags:
  - phishing
  - credential-theft
  - MFA-bypass
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
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.crowdstrike.com/en-us/blog/tycoon2fa-phishing-as-a-service-platform-persists-following-takedown/
rules:
  - title: Detect Credential Proxying via Suspicious Process Creation
    description: Detects suspicious process creation events where JavaScript or other scripting engines are used to proxy credentials to external domains, a technique used by Tycoon2FA.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Cookie Stealing via JavaScript
    description: Detects suspicious JavaScript activity attempting to access and exfiltrate cookie data, often associated with session hijacking.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Tycoon2FA is a subscription-based Phishing-as-a-Service (PhaaS) platform that allows cybercriminals to bypass multi-factor authentication (MFA) and compromise email accounts. The platform utilizes adversary-in-the-middle (AITM) techniques to intercept live authentication sessions. On March 4, 2026, Europol announced a technical disruption of Tycoon2FA, seizing 330 domains that formed the platform's infrastructure. Despite this takedown, CrowdStrike Falcon Complete observed a short-term decrease…
