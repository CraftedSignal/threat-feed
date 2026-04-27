---
title: Okta Admin Console Unusual Behavior Detection
slug: 2024-05-okta-admin-console-behaviors
description: This brief details detection of anomalous activity within the Okta Admin Console, potentially indicating privilege escalation, persistence, defense evasion, or initial access attempts by malicious actors.
date: "2024-05-02T10:00:00Z"
severities:
  - high
tags:
  - okta
  - identity
  - privilege-escalation
  - persistence
  - defense-evasion
  - initial-access
vendors:
  - Okta
products:
  - Okta Identity Engine
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection
  - https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_new_behaviours_admin_console.yml
rules:
  - title: Okta Admin Console Unusual Behavior
    description: Detects unusual behavior when accessing the Okta Admin Console as flagged by Okta.
    platform: sigma
    severity: high
    tactics:
      - defense-evasion
      - initial-access
      - persistence
      - privilege-escalation
    techniques:
      - T1078.004
    data_sources:
      - okta
      - okta
  - title: Okta Admin Console First Time Access
    description: Detects first-time access to the Okta Admin Console, which may indicate a new or compromised account.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
    techniques:
      - T1078
    data_sources:
      - okta
      - okta
rules_count: 2
---

This threat brief focuses on detecting unusual behaviors within the Okta Admin Console, as identified by Okta's heuristics. While the specific campaign details are unknown, identifying anomalous access patterns to the Admin Console is crucial for detecting various malicious activities. This includes potential privilege escalation by compromised accounts or insider threats attempting to gain elevated permissions, establishing persistence through unauthorized modifications, evading existing…
