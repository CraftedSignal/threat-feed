---
title: Okta Group Application Assignment Spike Indicates Privilege Escalation
slug: 2024-01-okta-group-app-assignment-spike
description: A machine learning job identified a spike in Okta group application assignment changes, potentially indicating threat actors escalating privileges, maintaining persistence, or moving laterally by assigning applications to groups.
date: "2024-01-03T12:00:00Z"
severities:
  - low
tags:
  - privileged-access
  - privilege-escalation
  - okta
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
  - title: Okta - Unusual Group Application Assignment Changes
    description: Detects unusual Okta group application assignment changes based on the event type and actor, potentially indicating malicious activity.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - webserver
      - okta
  - title: Okta - Spike in Group Application Assignments
    description: Detects a rapid increase in Okta group application assignments within a short period, potentially indicating unauthorized activity or privilege escalation attempts.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - webserver
      - okta
rules_count: 2
---

A machine learning job, `pad_okta_spike_in_group_application_assignment_changes_ea`, has detected an unusual spike in Okta group application assignment change events. This activity, monitored by the Privileged Access Detection integration, suggests potential malicious activity where threat actors may be assigning applications to groups to escalate access, maintain persistence, or facilitate lateral movement. This is particularly relevant for organizations using Okta for identity and access…
