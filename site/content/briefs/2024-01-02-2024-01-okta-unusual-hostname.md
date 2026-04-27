---
title: Okta Privileged Operations from Unusual Host Name Detected
slug: 2024-01-okta-unusual-hostname
description: A machine learning job detected a user performing privileged operations in Okta from an uncommon device, potentially indicating a compromised account or insider threat attempting privilege escalation.
date: "2024-01-02T12:00:00Z"
severities:
  - low
tags:
  - privileged-access-detection
  - okta
  - machine-learning
  - privilege-escalation
mitre_ttps:
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
  - title: Okta - Privileged Operations from New Hostname
    description: Detects a user performing privileged operations in Okta from a previously unseen hostname, which could indicate account compromise or insider threat.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1078.004
    data_sources:
      - webserver
      - okta
  - title: Okta - Multiple Failed Logins followed by Privileged Access
    description: Detects multiple failed login attempts from the same user followed by a successful login and subsequent privileged operation, indicating potential credential stuffing or brute-force attack.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - webserver
      - okta
rules_count: 2
---

This alert identifies potentially malicious Okta activity based on unusual host names associated with privileged operations. The Elastic prebuilt machine learning job `pad_okta_rare_host_name_by_user_ea` analyzes Okta logs to detect anomalies in device usage, specifically focusing on unusual host names. This activity could indicate a compromised user account, an attacker using stolen credentials, or an insider threat leveraging an unauthorized device to escalate privileges within the Okta…
