---
title: Detection of Okta Administrator Role Assignment to User or Group
slug: 2024-01-03-okta-admin-role-assignment
description: Detects the assignment of an Okta administrator role to a user or group, potentially indicating privilege escalation or persistence attempts by malicious actors.
date: "2024-01-03T12:00:00Z"
severities:
  - medium
tags:
  - privilege-escalation
  - persistence
  - okta
vendors:
  - Okta
products:
  - Okta
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://developer.okta.com/docs/reference/api/event-types/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_admin_role_assigned_to_user_or_group.yml
rules:
  - title: Okta Admin Role Assigned to User or Group
    description: Detects when the Administrator role is assigned to a user or group in Okta.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1098.003
    data_sources:
      - okta
      - okta
  - title: Okta Group Privilege Grant Activity
    description: Detects granting of privileges to a group in Okta, which can be used for privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - privilege-escalation
    techniques:
      - T1098.003
    data_sources:
      - okta
      - okta
rules_count: 2
---

The assignment of administrator roles within Okta to users or groups is a sensitive action that requires careful monitoring. While legitimate administrator actions can account for these events, malicious actors may attempt to escalate privileges or establish persistence by assigning themselves or their controlled groups administrative rights. This activity could lead to unauthorized access, data breaches, or disruption of services within the Okta environment. Defenders should prioritize…
