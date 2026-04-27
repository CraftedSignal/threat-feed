---
title: Unusual Host Name for Windows Privileged Operations Detected via ML
slug: 2024-01-02-unusual-windows-privileged-access
description: A machine learning job has identified a user performing privileged operations in Windows from an uncommon device, indicating potential privileged access activity associated with compromised accounts or insider threats.
date: "2024-01-02T15:00:00Z"
severities:
  - low
tags:
  - privileged-access-detection
  - anomaly-detection
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/pad
rules:
  - title: Windows Privileged Operations from Rare Host - Process Creation
    description: Detects process creation events associated with privileged operations originating from a host that is rarely used by the user.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - process_creation
      - windows
  - title: Windows Privileged Operations from Rare Host - Network Connection
    description: Detects network connections from processes associated with privileged operations originating from a host that is rarely used by the user.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This threat brief describes the detection of unusual privileged access activity in Windows environments. The detection leverages a machine learning model ("pad_windows_rare_device_by_user_ea") designed to identify deviations from typical host usage patterns. Specifically, it flags instances where a user performs privileged operations from a device not commonly associated with that user. This activity can indicate a compromised account where an attacker is using stolen credentials or an insider…
