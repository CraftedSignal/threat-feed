---
title: Unusual Source IP for Windows Privileged Operations Detected via ML
slug: 2024-01-unusual-source-ip-privileged-ops
description: A machine learning job detected a user performing privileged operations in Windows from an uncommon source IP, potentially indicating account compromise or privilege escalation.
date: "2024-01-02T15:00:00Z"
severities:
  - low
tags:
  - privileged-access-detection
  - machine-learning
  - windows
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
  - title: Windows Privileged Operations from Unusual Source IP (Process Creation)
    description: Detects process creations indicative of privileged operations originating from rare or unusual source IPs.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - process_creation
      - windows
  - title: Windows Privileged Operations from Unusual Source IP (Network Connection)
    description: Detects network connections associated with privileged operations originating from rare or unusual source IPs.
    platform: sigma
    severity: low
    tactics:
      - lateral_movement
    techniques:
      - T1078
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This alert leverages Elastic's machine learning capabilities to identify anomalous network activity related to privileged operations in Windows. Specifically, it flags instances where a user performs privileged actions from a source IP address that is not typically associated with their account. The detection rule, `Unusual Source IP for Windows Privileged Operations Detected`, is triggered by the `pad_windows_rare_source_ip_by_user_ea` machine learning job. The underlying machine learning…
