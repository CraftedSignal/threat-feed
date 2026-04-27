---
title: Okta Group Privilege Change Spike via ML Detection
slug: 2024-01-okta-group-privilege-spike
description: A machine learning job has identified an unusual spike in Okta group privilege change events, indicating potential privileged access activity where attackers might be elevating privileges by adding themselves or compromised accounts to high-privilege groups, enabling further access or persistence.
date: "2024-01-03T12:00:00Z"
severities:
  - medium
tags:
  - okta
  - privilege-escalation
  - machine-learning
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
  - title: Okta Suspicious Group Membership Changes
    description: Detects suspicious Okta group membership changes that may indicate privilege escalation attempts
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - webserver
      - linux
  - title: Okta Brute Force or Credential Stuffing Attempts
    description: Detects multiple failed Okta login attempts from the same IP address, which might indicate brute force or credential stuffing attacks.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1110
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This alert focuses on detecting potential privilege escalation attempts within Okta environments. The Elastic Security prebuilt machine learning job `pad_okta_spike_in_group_privilege_changes_ea` identifies unusual spikes in Okta group privilege change events. Attackers may add themselves or compromised accounts to high-privilege groups to gain unauthorized access and persist within the environment. This activity can lead to significant data breaches, system compromise, and long-term…
