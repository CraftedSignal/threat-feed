---
title: Tycoon2FA Phishing-as-a-Service Platform Resurgence After Takedown
slug: 2026-04-tycoon2fa-resurgence
description: The Tycoon2FA Phishing-as-a-Service (PhaaS) platform, which bypasses multifactor authentication (MFA) to compromise email accounts, experienced a temporary disruption following a law enforcement takedown, but campaign volumes and tactics have returned to pre-disruption levels, indicating the actors are likely to remain active.
date: "2026-03-28T14:49:20Z"
severities:
  - high
tags:
  - phishing
  - mfa bypass
  - credential theft
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
  - title: Detect Suspicious Javascript Cookie Theft
    description: Detects Javascript attempting to access or modify document.cookie which could indicate cookie theft.
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
    description: Detects access to fake Microsoft 365 or Google login pages.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - webserver
      - linux
  - title: Detect CAPTCHA Page Access Prior to Login Attempt
    description: Detects access to a CAPTCHA page followed by a login attempt within a short timeframe, which is indicative of Tycoon2FA's technique.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - webserver
      - linux
rules_count: 3
---

On March 4, 2026, Europol announced the takedown of Tycoon2FA, a subscription-based phishing-as-a-service (PhaaS) platform used by cybercriminals to bypass multi-factor authentication (MFA) and compromise email accounts. The coordinated effort involved law enforcement agencies from six countries and resulted in the seizure of 330 domains that constituted the platform's core infrastructure. Despite this disruption, CrowdStrike Falcon Complete observed a short-term decrease in Tycoon2FA campaign…
