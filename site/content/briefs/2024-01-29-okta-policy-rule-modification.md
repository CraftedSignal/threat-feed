---
title: Okta Policy Rule Modification or Deletion
slug: 2024-01-29-okta-policy-rule-modification
description: An Okta policy rule was modified or deleted, potentially weakening security controls.
date: "2024-01-29T12:00:00Z"
severities:
  - medium
tags:
  - okta
  - identity
  - policy
  - attack.impact
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
rules:
  - title: Okta Policy Rule Modified or Deleted
    description: Detects when an Okta Policy Rule is Modified or Deleted.
    platform: sigma
    severity: medium
    tactics:
      - impact
    data_sources:
      - okta
      - okta
  - title: Okta Policy Rule Update with MFA Disabled
    description: Detects modifications to Okta policy rules that disable or weaken MFA requirements.
    platform: sigma
    severity: high
    tactics:
      - impact
      - privilege_escalation
    data_sources:
      - okta
      - okta
rules_count: 2
---

Okta is a widely used identity and access management platform. Threat actors may target Okta configurations to weaken an organization's security posture. This activity involves modifications or deletions of policy rules within Okta. Such changes can reduce the effectiveness of multi-factor authentication (MFA) requirements, bypass access controls, or disable security logging. Detection of these changes is crucial to maintaining a strong security baseline and preventing unauthorized access to…
