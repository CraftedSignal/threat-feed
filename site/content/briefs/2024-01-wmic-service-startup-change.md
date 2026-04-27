---
title: Service Startup Type Modification via WMIC
slug: 2024-01-wmic-service-startup-change
description: Adversaries use the Windows Management Instrumentation Command-line (WMIC) utility to modify the startup type of services, setting them to 'Manual' or 'Disabled' to impair defenses or disrupt system operations.
date: "2024-01-03T12:00:00Z"
severities:
  - medium
tags:
  - attack.execution
  - attack.t1047
  - attack.defense-evasion
  - attack.t1562.001
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows 10
  - Windows 11
  - Windows Server 2016
  - Windows Server 2019
  - Windows Server 2022
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1047
    technique_name: Windows Management Instrumentation
references:
  - https://blog.talosintelligence.com/uncovering-qilin-attack-methods-exposed-through-multiple-cases/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_wmic_service_startup_change.yml
rules:
  - title: WMIC Service Startup Type Change to Manual or Disabled
    description: Detects changes to service startup type to 'disabled' or 'manual' using the WMIC command-line utility.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
      - execution
    techniques:
      - T1047
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: WMIC Service Startup Type Change to Manual or Disabled (CommandLine Contains)
    description: Detects changes to service startup type to 'disabled' or 'manual' using the WMIC command-line utility. This rule uses command line contains instead of endswith for image.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
      - execution
    techniques:
      - T1047
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may leverage WMIC, a legitimate Windows command-line utility, to modify the startup type of services. This tactic is often used to disable security products or critical system services, hindering incident response or creating system instability. By setting services to "Manual" or "Disabled", adversaries ensure that these services do not automatically start upon system boot, achieving persistence or impeding detection. While WMIC is a built-in tool, its use for modifying service…
