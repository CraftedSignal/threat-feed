---
title: Unusual Process Spawned by a Parent Process via Machine Learning
slug: 2024-01-unusual-process-spawn
description: A machine learning job detected a suspicious Windows process, predicted malicious by the ProblemChild model and flagged as an unusual child process name for its parent, potentially indicating LOLbins usage and evading traditional detection.
date: "2024-01-23T12:00:00Z"
severities:
  - low
tags:
  - defense-evasion
  - lolbins
  - windows
  - machine-learning
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/problemchild
  - https://www.elastic.co/security-labs/detecting-living-off-the-land-attacks-with-new-elastic-integration
rules:
  - title: Suspicious Process Spawned by Common LOLBin
    description: Detects a rare process spawned by a common LOLBin like powershell.exe or cmd.exe. Relies on process creation events.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: Rare Process Executed by WMI
    description: Detects execution of a rare process initiated via Windows Management Instrumentation (WMI).
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This alert originates from an Elastic machine learning job named `problem_child_rare_process_by_parent_ea` designed to detect Living off the Land (LotL) attacks on Windows systems. The model identifies processes spawned by parent processes that are statistically rare and have a high probability of being malicious based on the "ProblemChild" supervised learning model. This approach aims to uncover malicious activities that utilize legitimate system binaries (LOLbins) for nefarious purposes…
