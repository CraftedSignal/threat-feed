---
title: Windows System Restore Disabled via Registry Modification
slug: 2024-01-03-disable-system-restore
description: Attackers disable Windows System Restore by modifying specific registry keys to hinder recovery efforts after malicious activity.
date: "2024-01-03T12:00:00Z"
severities:
  - medium
tags:
  - impact
  - t1490
  - persistence
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows 10
  - Windows 11
  - Windows Server 2019
  - Windows Server 2022
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1490/T1490.md#atomic-test-9---disable-system-restore-through-registry
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_system_restore.yml
rules:
  - title: Registry Disable System Restore Modified
    description: Detects modification of the registry to disable system restore
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - registry_set
      - windows
  - title: Registry Disable System Restore via reg.exe
    description: Detects disabling system restore via reg.exe command
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may disable the Windows System Restore feature to prevent victims from easily reverting their systems to a clean state after an infection or other malicious activity. This action complicates incident response and remediation efforts, forcing more complex and time-consuming recovery procedures. Disabling system restore is often performed post-compromise to ensure persistence and hinder forensic analysis. This technique can be implemented manually through the registry editor or via…
