---
title: Okta Application Modified or Deleted
slug: 2024-01-03-okta-app-modified-deleted
description: Detects when an Okta application is modified or deleted, potentially indicating unauthorized changes or removal of critical applications.
date: "2024-01-03T12:00:00Z"
severities:
  - medium
tags:
  - okta
  - application-security
  - identity-management
vendors:
  - Okta
products:
  - Okta
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://developer.okta.com/docs/reference/api/event-types/
rules:
  - title: Okta Application Modified or Deleted
    description: Detects when an application is modified or deleted in Okta.
    platform: sigma
    severity: medium
    tactics:
      - impact
    data_sources:
      - okta
      - okta
  - title: Okta Application Update with Suspicious Scope Change
    description: Detects when an application's scope is modified in Okta, potentially granting unauthorized access.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - okta
      - okta
rules_count: 2
---

This alert detects modifications or deletions of applications within the Okta identity and access management platform. While the specific actor is unknown, the modification or deletion of an application can lead to significant disruptions and potential security breaches. The activity is detected through Okta system logs that record application lifecycle events. This is crucial for defenders because unauthorized changes to applications can lead to privilege escalation, data breaches, or denial…
