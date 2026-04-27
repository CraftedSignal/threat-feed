---
title: RegPwnBOF Registry Symlink Race Condition Exploit
slug: 2024-01-regpwnbof
description: RegPwnBOF exploits a registry symlink race condition in the Windows Accessibility ATConfig mechanism, enabling a normal user to write arbitrary values to protected HKLM registry keys for persistence and privilege escalation.
date: "2026-03-19T05:23:44Z"
severities:
  - high
tags:
  - registry
  - symlink
  - race-condition
  - accessibility
  - privilege-escalation
  - persistence
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rxrt45/regpwnbof_bof_of_regpwn_exploits_a_registry/
  - https://github.com/Flangvik/RegPwnBOF
rules:
  - title: Detect Suspicious Registry Symlink Creation
    description: Detects the creation of registry symlinks potentially used for privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Modification of Accessibility Settings via ATConfig
    description: Detects modification of registry keys associated with accessibility features which may indicate RegPwnBOF activity.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

RegPwnBOF is an exploit leveraging a registry symlink race condition within the Windows Accessibility ATConfig mechanism. This vulnerability allows an unprivileged user to manipulate protected areas of the registry, specifically HKLM, which are typically reserved for administrators or system processes. By exploiting this race condition, an attacker can write arbitrary values to these protected keys. The initial report surfaced around March 2026, highlighting the potential for unauthorized…
