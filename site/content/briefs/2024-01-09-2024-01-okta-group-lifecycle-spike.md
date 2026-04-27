---
title: Okta Group Lifecycle Change Spike Indicating Privilege Escalation
slug: 2024-01-okta-group-lifecycle-spike
description: A machine learning job has identified an unusual spike in Okta group lifecycle change events, indicating potential privilege escalation activity, where adversaries may be altering group structures to escalate privileges, maintain persistence, or facilitate lateral movement within an organization’s identity management system.
date: "2024-01-09T12:00:00Z"
severities:
  - low
tags:
  - privileged-access
  - okta
  - group-lifecycle
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
  - title: Okta Group Membership Changes by New User
    description: Detects when a user account, recently created (within last 24h), is added to an Okta group, which may indicate suspicious privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1098.007
    data_sources:
      - webserver
      - okta
  - title: Okta Group Deletion Followed by Recreation
    description: Detects the deletion of an Okta group followed by the recreation of a group with the same name within a short timeframe, potentially for malicious purposes such as impersonation or bypassing controls.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - webserver
      - okta
rules_count: 2
---

This alert identifies potential privileged access activity within Okta environments by detecting unusual spikes in group lifecycle change events. The activity is detected using Elastic's Anomaly Detection feature. Adversaries may manipulate group structures to achieve privilege escalation, establish persistence, or move laterally within an organization. The anomaly detection job, `pad_okta_spike_in_group_lifecycle_changes_ea`, monitors these changes. This activity matters because unauthorized…
