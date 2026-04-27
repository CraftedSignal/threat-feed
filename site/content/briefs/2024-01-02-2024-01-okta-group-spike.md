---
title: Okta Group Membership Spike Detection
slug: 2024-01-okta-group-spike
description: A machine learning job has identified an unusual spike in Okta group membership events, indicating potential privileged access activity where attackers or malicious insiders might be adding accounts to privileged groups to escalate their access, potentially leading to unauthorized actions or data breaches.
date: "2024-01-02T12:00:00Z"
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
  - title: Okta - Spike in Group Membership Changes
    description: Detects a spike in Okta group membership changes, potentially indicating malicious privilege escalation activity.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - webserver
      - okta
  - title: Okta - Account Added to Privileged Group
    description: Detects when an account is added to a group with high privileges.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - webserver
      - okta
rules_count: 2
---

This rule leverages machine learning to detect unusual spikes in Okta group membership events, potentially indicating privileged access activity. The detection logic is based on the "pad_okta_spike_in_group_membership_changes_ea" machine learning job. The rule aims to identify scenarios where attackers or malicious insiders are adding accounts to privileged groups within Okta to escalate their privileges, which could lead to unauthorized actions and data breaches. This rule requires the…
