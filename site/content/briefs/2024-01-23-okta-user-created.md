---
title: Okta User Account Created
slug: 2024-01-23-okta-user-created
description: Detection of new user account creation in Okta, which could indicate malicious activity related to credential access.
date: "2024-01-23T12:00:00Z"
severities:
  - low
tags:
  - okta
  - identity
  - user-creation
  - credential-access
vendors:
  - Okta
products:
  - Okta
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://developer.okta.com/docs/reference/api/event-types/
rules:
  - title: Okta - New User Created via API
    description: Detects new user creation events in Okta logs specifically initiated via the Okta API.
    platform: sigma
    severity: informational
    tactics:
      - credential-access
    data_sources:
      - okta
      - okta
  - title: Okta - New User Created with Specific Role
    description: Detects new user creation events in Okta logs where a specific role is assigned during creation.
    platform: sigma
    severity: medium
    tactics:
      - credential-access
      - privilege_escalation
    data_sources:
      - okta
      - okta
rules_count: 2
---

This alert detects the creation of new user accounts within an Okta environment. While legitimate user creation is common, malicious actors may create accounts to gain unauthorized access to resources, escalate privileges, or establish persistence within the network. Monitoring for anomalous user creation activity, such as accounts created outside of normal business hours or with suspicious naming conventions, is crucial for identifying potential security breaches. Reviewing the source IP and…
