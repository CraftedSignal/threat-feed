---
title: Tycoon2FA Phishing-as-a-Service Platform Resurgence
slug: 2026-03-tycoon2fa-resurgence
description: The Tycoon2FA phishing-as-a-service (PhaaS) platform, which enables cybercriminals to bypass multifactor authentication (MFA) and compromise email accounts, has shown resilience following a takedown attempt by Europol on March 4, 2026, with campaign activity returning to pre-disruption levels and consistent TTPs.
date: "2026-03-30T06:40:37Z"
severities:
  - high
tags:
  - phishing
  - MFA-bypass
  - cloud-compromise
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
  - title: Detect JavaScript Email Address Extraction
    description: Detects JavaScript files used to extract email addresses, a technique used by Tycoon2FA.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - file_event
      - windows
  - title: Detect Fake Microsoft 365 Login Page Access
    description: Detects access to domains known to host fake Microsoft 365 login pages, a common tactic used in phishing campaigns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - network_connection
      - windows
  - title: Detect suspicious process creating network connections
    description: Detects processes making network connections that are not usually associated with network activity
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

The Tycoon2FA phishing-as-a-service (PhaaS) platform, disrupted by Europol on March 4, 2026, has demonstrated a resurgence in activity, indicating the platform's operators remain active and adaptable. Tycoon2FA, active since 2023, enables cybercriminals to bypass multifactor authentication (MFA) and compromise email accounts through adversary-in-the-middle (AITM) techniques. Before the takedown, in mid-2025, it was responsible for 62% of all phishing attempts blocked by Microsoft and…
