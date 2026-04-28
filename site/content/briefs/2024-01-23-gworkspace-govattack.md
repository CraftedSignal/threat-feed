---
title: Google Workspace Login Attempt with Government Attack Warning
slug: 2024-01-23-gworkspace-govattack
description: A Google Workspace login attempt flagged as a potential attack by a government-backed threat actor, indicating potential privilege escalation, defense evasion, persistence, initial access, or impact.
date: "2026-04-28T00:48:14Z"
severities:
  - medium
tags:
  - googleworkspace
  - intrusion
  - initial-access
  - persistence
  - privilege-escalation
vendors:
  - Google
products:
  - Google Workspace
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://cloud.google.com/logging/docs/audit/gsuite-audit-logging
  - https://cloud.google.com/logging/docs/audit/understanding-audit-logs
  - https://developers.google.com/workspace/admin/reports/v1/appendix/activity/login#gov_attack_warning
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/gcp/gworkspace/login/gcp_gworkspace_govattack.yml
rules:
  - title: Google Workspace Login with Government Attack Warning
    description: Detects a login attempt in Google Workspace flagged as a potential attack by a government-backed threat actor
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
      - impact
      - initial-access
      - persistence
      - privilege-escalation
    techniques:
      - T1078
    data_sources:
      - gcp
      - google_workspace.login
  - title: Google Workspace Unusual Login Location with Gov Attack Warning
    description: Detects login from an unusual location flagged as gov_attack_warning
    platform: sigma
    severity: high
    tactics:
      - initial-access
    techniques:
      - T1078
    data_sources:
      - gcp
      - google_workspace.login
rules_count: 2
---

This alert focuses on identifying potentially malicious login attempts within Google Workspace environments. The detection is based on Google's own flagging of a login as a potential "gov_attack_warning," suggesting that Google's threat intelligence attributes the activity to a government-backed actor. While specific targeting information is unavailable, this alert highlights a critical area for investigation within organizations utilizing Google Workspace, especially those handling sensitive…
