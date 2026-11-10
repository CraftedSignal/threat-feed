---
brief_id: brief-2026-11-10-wmi-persistence
event_id: brief-2026-11-10-wmi-persistence
revision: 1
activity_at: "2026-11-10T08:45:58Z"
title: WMI Persistence - Security
slug: 2026-11-wmi-persistence
description: Detection of suspicious WMI event filter and command line event consumer based on WMI and Security Logs.
date: "2026-11-10T08:45:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
references:
  - https://web.archive.org/web/20170821162638/https://twitter.com/mattifestation/status/899646620148539397
  - https://web.archive.org/web/20250427230247/https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_wmi_persistence.yml
rules:
  - title: Detect WMI Event Subscription Access
    description: Detects suspicious WMI event filter and command line event consumer based on WMI and Security Logs.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1546.003
    data_sources:
      - windows
      - security
rules_count: 1
---

This detection identifies suspicious WMI event filter and command line event consumer activity. The rule monitors the Windows Security log for Event ID 4662, specifically looking for access to WMI namespaces containing the term "subscription."
