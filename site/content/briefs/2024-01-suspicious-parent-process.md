---
title: Suspicious Windows Process Cluster from Parent Process via Machine Learning
slug: 2024-01-suspicious-parent-process
description: A machine learning model detected a parent process spawning a cluster of suspicious Windows processes with high malicious probability scores, potentially indicating LOLBins usage and defense evasion.
date: "2024-01-30T12:00:00Z"
severities:
  - medium
tags:
  - defense-evasion
  - lolbin
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
  - title: Suspicious Windows Process Spawning from Common System Process
    description: Detects instances where a known system process spawns a suspicious Windows process with a high malicious probability, potentially indicating LOLBins usage.
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
  - title: Suspicious Process Cluster Detection via Parent-Child Relationship
    description: Detects clusters of suspicious processes originating from the same parent process, leveraging process creation events.
    platform: sigma
    severity: low
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

This alert leverages Elastic's ProblemChild integration to detect potential Living off the Land (LotL) attacks on Windows systems. The rule utilizes a combination of supervised and unsupervised machine learning models to identify parent processes spawning clusters of suspicious child processes. These child processes are flagged as having unusually high malicious probability scores, suggesting the use of LOLBins or other defense evasion techniques. The detection focuses on identifying groups of…
