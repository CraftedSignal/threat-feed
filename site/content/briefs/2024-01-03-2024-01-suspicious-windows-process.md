---
title: Suspicious Windows Process Cluster Detection via Machine Learning
slug: 2024-01-suspicious-windows-process
description: A machine learning job combination has identified a host with one or more suspicious Windows processes that exhibit unusually high malicious probability scores, potentially indicating masquerading and defense evasion tactics.
date: "2024-01-03T18:00:00Z"
severities:
  - low
tags:
  - defense-evasion
  - masquerading
  - LOLbins
  - windows
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
  - title: Detect Potential LOLBin Execution via Image Path
    description: Detects potential LOLBin execution by monitoring process creations from non-standard system directories. This rule looks for processes spawned from unusual locations, which could indicate an attempt to masquerade malicious activity.
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
  - title: Detect Suspicious Process Spawning LOLBins
    description: Detects potentially suspicious process spawning LOLBins, such as cmd.exe, powershell.exe or mshta.exe, from unusual parent processes. It helps identify potentially malicious processes trying to leverage LOLBins for nefarious activities.
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

This detection identifies suspicious Windows processes exhibiting high malicious probability scores. The rule leverages machine learning to detect clusters of processes that may be indicative of defense evasion tactics, such as masquerading or the use of LOLbins (Living Off The Land Binaries). Specifically, a supervised ML model (ProblemChild) predicts whether a process is malicious, and an unsupervised ML model assesses the aggregate score of process clusters on a single host. The rule focuses…
