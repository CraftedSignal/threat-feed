---
title: Spike in Special Privilege Use Events
slug: 2024-01-spike-privilege-use
description: A machine learning job detected an unusual increase in special privilege usage events on Windows, such as privileged operations and service calls, potentially indicating unauthorized privileged access and privilege escalation attempts.
date: "2024-01-03T15:00:00Z"
severities:
  - low
tags:
  - privileged-access-detection
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
    technique_id: T1134
    technique_name: Access Token Manipulation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1134
    technique_name: Access Token Manipulation
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/pad
rules:
  - title: Detect Potential Access Token Manipulation via SeDebugPrivilege
    description: Detects processes enabling the SeDebugPrivilege, often used in access token manipulation attacks.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1134
    data_sources:
      - process_creation
      - windows
  - title: Detecting Unusual Service Account Usage
    description: Detects processes running under a service account that are initiating network connections, which is often unusual.
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

This detection identifies unusual spikes in special privilege use events on Windows systems, leveraging machine learning to detect anomalies. The rule, designed for the Elastic platform, uses the "pad_windows_high_count_special_privilege_use_events_ea" machine learning job to identify deviations from established baselines of user behavior related to privileged operations. The rule focuses on events collected via the Elastic Defend and Windows integrations. A sudden increase in these events may…
