---
title: RustFS Notification Target Admin API Authorization Bypass
slug: 2024-01-rustfs-admin-auth-bypass
description: A vulnerability in RustFS allows a non-admin user to overwrite a shared admin-defined notification target, leading to event interception and audit evasion due to missing admin-action authorization on notification target admin API endpoints.
date: "2024-01-02T12:00:00Z"
severities:
  - high
tags:
  - authorization-bypass
  - ssrf
  - event-interception
vendors:
  - rustfs
products:
  - rustfs
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
references:
  - https://github.com/advisories/GHSA-pfcq-4gjr-6gjm
rules:
  - title: Detect RustFS Notification Target Manipulation
    description: Detects attempts to manipulate RustFS notification targets via the admin API, indicating a potential authorization bypass.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: Detect Outbound Connection to Potential Attacker-Controlled Endpoint from RustFS
    description: Detects outbound connection to attacker controlled server based on attacker controlled endpoint
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A critical authorization bypass vulnerability exists in RustFS versions 0.0.2 and earlier, specifically within the notification target admin API endpoints (`rustfs/src/admin/handlers/event.rs`). These endpoints lack proper admin-action authorization, failing to call `validate_admin_request`. This oversight allows a non-admin user to overwrite admin-defined notification targets by name. Successful exploitation enables attackers to intercept events intended for legitimate administrators and evade…
