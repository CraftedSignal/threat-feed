---
title: ProblemChild ML Detection of Suspicious Windows Processes
slug: 2024-01-problemchild-suspicious-windows-processes
description: The ProblemChild machine learning model has detected a user with suspicious Windows processes exhibiting unusually high malicious probability scores, potentially indicating defense evasion via masquerading or LOLbins.
date: "2024-01-22T12:00:00Z"
severities:
  - medium
tags:
  - defense-evasion
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
  - title: Detect Suspicious Process Execution via LOLBins
    description: Detects the execution of known LOLBins with command line arguments often associated with malicious activities
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Image Masquerading
    description: Detects processes masquerading as legitimate system binaries by renaming or copying themselves
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Elastic ProblemChild integration leverages machine learning to identify suspicious Windows process clusters associated with specific users. This detection focuses on processes flagged as malicious by a supervised ML model, further refined by an unsupervised ML model that identifies unusually high aggregate scores within process clusters. This combination aims to detect activity that may evade traditional signature-based detections, such as the use of Living-off-the-Land Binaries (LOLbins)…
