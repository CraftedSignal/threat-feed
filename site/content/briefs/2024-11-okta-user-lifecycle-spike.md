---
title: Unusual Spike in Okta User Lifecycle Management Change Events
slug: 2024-11-okta-user-lifecycle-spike
description: A machine learning job has identified an unusual spike in Okta user lifecycle management change events, indicating potential privileged access activity where threat actors may manipulate user accounts to gain higher access rights or persist within the environment.
date: "2024-11-02T12:00:00Z"
severities:
  - low
tags:
  - privileged-access
  - okta
  - user-lifecycle
mitre_ttps:
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
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/pad
rules:
  - title: Okta User Role Modification
    description: Detects modifications to user roles in Okta, which can indicate privilege escalation or account compromise.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - webserver
      - linux
  - title: Okta User Creation Spike
    description: Detects a sudden increase in user account creation events in Okta, potentially indicating malicious activity.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This alert detects potential privileged access activity within an Okta environment. The detection is triggered by a machine learning job that identifies anomalous spikes in user lifecycle management change events. Threat actors may target user accounts to escalate their privileges or to establish persistence within the environment. This is achieved by manipulating user accounts, such as modifying roles, permissions, or other attributes. The prebuilt ML job…
