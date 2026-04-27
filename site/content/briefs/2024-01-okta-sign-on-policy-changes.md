---
title: Okta Application Sign-On Policy Modified or Deleted
slug: 2024-01-okta-sign-on-policy-changes
description: Attackers may modify or delete Okta application sign-on policies to weaken security controls, potentially leading to unauthorized access and data breaches.
date: "2024-01-03T12:00:00Z"
severities:
  - medium
tags:
  - identity
  - okta
  - policy-tampering
vendors:
  - Okta
products:
  - Okta
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://developer.okta.com/docs/reference/api/event-types/
rules:
  - title: Okta Application Sign-On Policy Modified or Deleted
    description: Detects when an application Sign-on Policy is modified or deleted.
    platform: sigma
    severity: medium
    tactics:
      - impact
    data_sources:
      - okta
      - okta
  - title: Okta Policy Modified by Non-Admin User
    description: Detects policy modifications when the actor is not a designated admin user.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - okta
      - okta
rules_count: 2
---

Okta application sign-on policies control how users authenticate to applications integrated with Okta. An attacker who gains administrative access to an Okta tenant can modify or delete these policies, effectively weakening or bypassing multi-factor authentication (MFA) requirements and other security controls. This allows unauthorized access to sensitive applications and data. While this activity itself is not initial access, it represents a significant escalation of privileges and a…
