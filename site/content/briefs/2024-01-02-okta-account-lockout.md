---
title: Okta User Account Lockout Detection
slug: 2024-01-02-okta-account-lockout
description: Detection of an Okta user account lockout, which may indicate brute-force attempts or other malicious activity targeting user accounts.
date: "2024-01-02T12:00:00Z"
severities:
  - medium
tags:
  - identity
  - account-lockout
  - okta
vendors:
  - Okta
products:
  - Okta
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1531
    technique_name: Account Access Removal
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://developer.okta.com/docs/reference/api/event-types/
rules:
  - title: Okta User Account Locked Out
    description: Detects when a user account is locked out due to exceeding the maximum number of sign-in attempts.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1531
    data_sources:
      - okta
      - okta
  - title: Okta Multiple User Account Lockouts in Short Time
    description: Detects multiple user account lockouts within a short timeframe, possibly indicating a widespread brute-force attack.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1531
    data_sources:
      - okta
      - okta
rules_count: 2
---

This brief describes detection measures for Okta user account lockouts. An account lockout occurs when a user exceeds the maximum number of permitted failed login attempts, potentially indicating a brute-force attack or other unauthorized access attempts against user accounts. Monitoring for account lockouts is crucial for identifying and mitigating potential security breaches. The rule detects the "Max sign in attempts exceeded" message in Okta logs, which signifies that an account has been…
