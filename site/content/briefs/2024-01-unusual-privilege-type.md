---
title: Unusual Privilege Type Assigned to User via Machine Learning Anomaly
slug: 2024-01-unusual-privilege-type
description: A machine learning job has identified a user leveraging an uncommon privilege type for privileged operations on Windows systems, potentially indicating privileged access activity and requiring investigation for privilege escalation or account manipulation.
date: "2024-01-02T15:00:00Z"
severities:
  - low
tags:
  - privileged-access
  - privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/pad
rules:
  - title: Detect PowerShell Privilege Attribute Manipulation
    description: Detects PowerShell scripts attempting to manipulate privilege attributes, a common technique for privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1547.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Account Manipulation via Net.exe
    description: Detects the use of net.exe to add accounts to privileged groups, potentially indicating malicious account manipulation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection leverages a machine learning job within the Elastic stack to identify anomalous privilege usage on Windows systems. Specifically, it flags instances where a user is observed utilizing a privilege type that deviates significantly from their established baseline behavior. The underlying machine learning model, `pad_windows_rare_privilege_assigned_to_user_ea`, analyzes Windows event logs collected via integrations like Elastic Defend and the Windows integration. This detection aims…
