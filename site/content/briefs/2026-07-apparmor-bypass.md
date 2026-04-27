---
title: AppArmor Policy Bypass via Direct File Manipulation
slug: 2026-07-apparmor-bypass
description: This rule detects processes attempting to bypass AppArmor protections by directly writing to AppArmor policy management files in `/sys/kernel/security/apparmor/`.
date: "2026-07-03T12:00:00Z"
severities:
  - medium
tags:
  - apparmor
  - defense-evasion
  - linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt
  - https://blog.qualys.com/vulnerabilities-threat-research/2026/03/12/crackarmor-critical-apparmor-flaws-enable-local-privilege-escalation-to-root
rules:
  - title: Suspicious AppArmor Policy Modification
    description: Detects processes attempting to modify AppArmor policies by writing to the /sys/kernel/security/apparmor directory.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - linux
  - title: Suspicious Shell Activity Writing to AppArmor
    description: Detects shell commands writing directly to AppArmor policy files.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - linux
  - title: Scripting Languages Writing to AppArmor Policy
    description: Detects scripting languages (Python, Perl, etc.) writing to AppArmor policy management files.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

This rule detects attempts to bypass AppArmor by directly writing to policy management files. AppArmor is a Linux kernel security module that provides mandatory access control, and direct manipulation of its policy files is highly unusual. The activity is triggered when processes attempt to load, replace, or remove AppArmor profiles by writing to the special kernel interfaces under `/sys/kernel/security/apparmor/`. While legitimate administrative tools like `apparmor_parser` handle policy…
