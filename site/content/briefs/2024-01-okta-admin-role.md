---
title: Okta Admin Role Assignment Creation
slug: 2024-01-okta-admin-role
description: Detection of new admin role assignments in Okta, potentially indicating privilege escalation or persistence attempts by malicious actors.
date: "2024-01-23T12:00:00Z"
severities:
  - medium
tags:
  - identity
  - okta
  - privilege-escalation
  - persistence
vendors:
  - Okta
products:
  - Okta
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://developer.okta.com/docs/reference/api/event-types/
rules:
  - title: Okta Admin Role Assignment Created
    description: Detects when a new admin role assignment is created in Okta, potentially indicating privilege escalation or persistence attempts.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    data_sources:
      - okta
      - okta
  - title: Okta Admin Role Assignment Modified
    description: Detects when an existing admin role assignment is modified, potentially indicating unauthorized changes to permissions.
    platform: sigma
    severity: low
    tactics:
      - persistence
    data_sources:
      - okta
      - okta
rules_count: 2
---

Okta is a widely used identity and access management (IAM) platform, making it a prime target for malicious actors seeking to gain unauthorized access to sensitive resources. This threat focuses on the creation of new admin role assignments within Okta. An attacker who successfully compromises an Okta account with sufficient privileges, or bypasses security controls, may attempt to escalate their privileges or establish persistence by creating new admin role assignments for themselves or other…
