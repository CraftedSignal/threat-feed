---
title: Unusual City for Azure Activity Logs Event
slug: 2026-06-unusual-azure-city
description: A machine learning job detected Azure Activity Logs activity that, while not inherently suspicious or abnormal, is sourcing from a geolocation (city) that is unusual for the event action, indicating potential compromised credentials.
date: "2026-04-02T13:35:13Z"
severities:
  - low
tags:
  - azure
  - cloud
  - anomaly-detection
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
rules:
  - title: Azure Activity Logs - Unusual City for Event Action
    description: Detects Azure Activity Logs events originating from an unusual city for the specific action, potentially indicating compromised credentials.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - cloudtrail
      - azure
  - title: Azure ARM - Privileged Role Assignment from Unusual City
    description: Detects privileged role assignments in Azure Resource Manager originating from an unusual city, indicating potential unauthorized elevation of privileges.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1078.004
    data_sources:
      - cloudtrail
      - azure
rules_count: 2
---

This detection identifies Azure Activity Logs activity originating from a city that is atypical for the specific event action being performed. The underlying mechanism is a machine learning job, `azure_activitylogs_rare_event_action_for_a_city_ea`, designed to surface anomalous geolocation patterns. The rule is triggered when the anomaly score exceeds 50. Such deviations can indicate compromised credentials used by an attacker operating from a different geography than the authorized user. This…
