---
title: Okta End-User Reports Suspicious Account Activity
slug: 2024-01-17-okta-suspicious-activity
description: An Okta end-user reports potentially suspicious activity on their account, indicating possible compromise or unauthorized access.
date: "2024-01-17T12:00:00Z"
severities:
  - medium
tags:
  - identity
  - okta
  - suspicious-activity
vendors:
  - Okta
products:
  - Okta
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1586
    technique_name: Compromise Accounts
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://github.com/okta/workflows-templates/blob/1164f0eb71ce47c9ddc7d850e9ab87b5a2b42333/workflows/suspicious_activity_reported/readme.md
rules:
  - title: Okta Suspicious Activity Reported by End-user
    description: Detects when an Okta end-user reports activity by their account as being potentially suspicious.
    platform: sigma
    severity: high
    tactics:
      - resource-development
    techniques:
      - T1586.003
    data_sources:
      - okta
      - okta
  - title: Okta User Password Reset Request Following Suspicious Activity Report
    description: Detects a password reset request shortly after a user reports suspicious activity, potentially indicating an attacker attempting to maintain access.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - resource-development
    techniques:
      - T1555.003
      - T1586.003
    data_sources:
      - okta
      - okta
rules_count: 2
---

This alert focuses on detecting when an end-user within an Okta environment reports suspicious activity related to their account. This is a critical indicator that the account may be compromised, or that unauthorized access has occurred. The activity is reported directly by the end-user. While this alert does not directly reveal the method of compromise, it serves as an important signal for security teams to investigate potentially malicious activity. This event triggers from an Okta system log…
