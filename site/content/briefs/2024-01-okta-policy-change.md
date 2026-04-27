---
title: Okta Policy Modification or Deletion Detected
slug: 2024-01-okta-policy-change
description: An Okta policy was modified or deleted, potentially indicating unauthorized changes to security configurations within the Okta identity management platform by a malicious actor or insider.
date: "2024-01-03T12:00:00Z"
severities:
  - low
tags:
  - identity
  - okta
  - policy
  - attack.impact
vendors:
  - Okta
products:
  - Okta Identity Cloud
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://developer.okta.com/docs/reference/api/event-types/
rules:
  - title: Okta Policy Modified or Deleted
    description: Detects when an Okta policy is modified or deleted.
    platform: sigma
    severity: low
    tactics:
      - impact
    data_sources:
      - okta
      - okta
  - title: Okta Policy Modified by Uncommon User Agent
    description: Detects Okta policy modifications originating from an unusual user agent.
    platform: sigma
    severity: medium
    tactics:
      - impact
      - privilege_escalation
    data_sources:
      - okta
      - okta
rules_count: 2
---

This alert identifies modifications or deletions of Okta policies, which govern authentication, authorization, and access control within the Okta Identity Cloud platform. While legitimate administrators routinely update policies, unauthorized changes can weaken security postures and grant malicious actors elevated privileges or bypass security controls. The source event indicates a potential compromise or insider threat activity within the Okta environment. Because Okta serves as a critical…
