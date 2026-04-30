---
title: System Restore Disabled via Registry Modification
slug: 2024-01-system-restore-disable
description: Attackers may attempt to disable system restore via registry modifications through the command line to prevent recovery after malicious activity.
date: "2024-01-03T14:30:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - attack.impact
  - attack.t1490
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1490/T1490.md#atomic-test-9---disable-system-restore-through-registry
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_reg_system_restore_modification.yml
rules:
  - title: System Restore Registry Modification via CommandLine
    description: Detects system restore registry modification via command line, which can be used by adversaries to disable system restore on the computer.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Attackers may attempt to disable the Windows System Restore feature to hinder forensic analysis and recovery efforts. This involves modifying specific registry keys related to System Restore configuration and operation, effectively preventing the system from creating or using restore points. The commands are executed via cmd, PowerShell or other scripting engines. Disabling System Restore can allow malware to operate without the risk of easy rollback, potentially increasing the impact of a…
