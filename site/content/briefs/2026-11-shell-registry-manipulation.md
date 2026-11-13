---
brief_id: brief-2026-11-13-shell-registry-manipulation
event_id: brief-2026-11-13-shell-registry-manipulation
revision: 1
activity_at: "2026-11-13T06:51:17Z"
title: Windows Registry Shell Open Key Manipulation
slug: 2026-11-shell-registry-manipulation
description: Malicious actors modify shell open command registry keys to achieve UAC bypass or maintain persistence through file association hijacking.
date: "2026-11-13T06:51:17Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - persistence
  - privilege-escalation
  - windows
  - registry
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548.002
    technique_name: Bypass User Account Control
    evidence: Detects manipulation of shell open command registry keys such as "ms-settings" and "exefile", which are commonly abused to achieve UAC bypass (e.g. via fodhelper.exe) or establish persistence through file association hijacking.
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546.001
    technique_name: Change Default File Association
    evidence: Detects manipulation of shell open command registry keys such as "ms-settings" and "exefile", which are commonly abused to achieve UAC bypass (e.g. via fodhelper.exe) or establish persistence through file association hijacking.
references:
  - https://github.com/hfiref0x/UACME
  - https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/
  - https://github.com/RhinoSecurityLabs/Aggressor-Scripts/tree/master/UACBypass
  - https://tria.ge/211119-gs7rtshcfr/behavioral2
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_event/registry_event_shell_open_keys_manipulation.yml
rules:
  - title: Detect Shell Open Registry Keys Manipulation
    description: Detects manipulation of shell open command registry keys such as 'ms-settings' and 'exefile', which are commonly abused to achieve UAC bypass or establish persistence through file association hijacking.
    platform: sigma
    severity: high
    data_sources:
      - registry_event
      - windows
rules_count: 1
---

Threat actors target Windows shell open command registry keys, such as "ms-settings" and "exefile", to facilitate User Account Control (UAC) bypass or to establish persistent execution via file association hijacking.

## Impact

Successful manipulation of these keys allows for privilege escalation to administrative levels or the establishment of long-term persistence within the host environment.

## Recommendation

Monitor registry events for unauthorized modifications to the identified shell open command keys.
