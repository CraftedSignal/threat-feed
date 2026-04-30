---
title: Okta Application Modified or Deleted
slug: 2024-01-03-okta-app-modified-deleted
description: Detects when an Okta application is modified or deleted, potentially indicating unauthorized changes or removal of critical applications.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
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

This alert detects modifications or deletions of applications within the Okta identity and access management platform. While the specific actor is unknown, the modification or deletion of an application can lead to significant disruptions and potential security breaches. The activity is detected through Okta system logs that record application lifecycle events. This is crucial for defenders because unauthorized changes to applications can lead to privilege escalation, data breaches, or denial of service. Monitoring these events allows for prompt investigation and mitigation of potentially malicious activity.

## Attack Chain

1.  Attacker gains unauthorized access to an Okta administrator account.
2.  The attacker authenticates to the Okta admin console.
3.  Attacker navigates to the Applications section in the Okta admin console.
4.  The attacker identifies a target application for modification or deletion.
5.  If modifying, the attacker alters application settings such as permissions, user assignments, or SSO configurations.
6.  If deleting, the attacker initiates the application deletion process.
7.  Okta logs the "application.lifecycle.update" or "application.lifecycle.delete" event.
8.  The change impacts end-users and their ability to access resources through the modified or deleted application.

## Impact

The impact of unauthorized application modification or deletion can be significant. Modified applications can grant unintended access to sensitive resources, leading to data breaches or privilege escalation. Deleted applications disrupt user access and business operations, potentially causing significant downtime and financial losses. The scope of the impact depends on the criticality of the affected application and the extent of the unauthorized changes.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect `application.lifecycle.update` or `application.lifecycle.delete` events in Okta logs.
*   Investigate any triggered alerts for unexpected application modifications or deletions, focusing on the user account that initiated the change (source: Okta logs).
*   Review Okta administrator account access and enforce multi-factor authentication to prevent unauthorized access (reference: Okta documentation on security best practices).
