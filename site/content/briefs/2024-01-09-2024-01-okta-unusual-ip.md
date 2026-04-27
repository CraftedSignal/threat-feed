---
title: Unusual Source IP for Okta Privileged Operations Detected
slug: 2024-01-okta-unusual-ip
description: A machine learning job has identified a user performing privileged operations in Okta from an uncommon source IP, indicating potential privileged access activity indicative of account compromise or privilege escalation.
date: "2024-01-09T10:00:00Z"
severities:
  - low
tags:
  - privileged-access
  - okta
  - machine-learning
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/pad
rules:
  - title: Okta User MFA Disabled followed by Privileged Operation
    description: Detects when a user account's MFA is disabled, followed by a privileged operation, potentially indicating an attacker preparing to escalate privileges. Focuses on Okta system logs related to user MFA status changes and subsequent administrative actions.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - webserver
      - linux
  - title: Okta User Logs In From Multiple Geographically-Distant Locations
    description: Detects Okta user logins originating from geographically distant locations within a short period, suggesting potential account sharing or compromise. Monitors Okta system logs for successful user authentication events and analyzes the IP addresses to determine their geographical location.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This alert leverages machine learning to identify deviations in IP usage patterns associated with privileged Okta operations, flagging unusual access attempts that could signify privilege escalation or account compromise. It identifies a user performing privileged operations in Okta from an uncommon source IP, potentially indicating account compromise, misuse of administrative privileges, or an attacker leveraging a new network location. The detection rule analyzes Okta logs, specifically…
