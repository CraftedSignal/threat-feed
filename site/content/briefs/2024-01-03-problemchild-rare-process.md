---
title: ProblemChild ML Model Detects Unusual Process on Windows Host
slug: 2024-01-03-problemchild-rare-process
description: The ProblemChild machine learning model detected a rare Windows process indicative of defense evasion, potentially involving LOLbins, on a host not commonly associated with malicious activity.
date: "2024-01-03T10:00:00Z"
severities:
  - low
tags:
  - defense-evasion
  - lolbin
  - windows
  - machine-learning
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/problemchild
  - https://www.elastic.co/security-labs/detecting-living-off-the-land-attacks-with-new-elastic-integration
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: Suspicious Process Execution via LOLbins
    description: Detects the execution of suspicious processes via Living off the Land binaries (LOLbins)
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: Suspicious MSHTA Execution
    description: Detects suspicious execution of MSHTA
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection leverages the ProblemChild supervised machine learning model to identify unusual Windows processes that may be indicative of defense evasion tactics. The model flags processes that are both statistically unusual for a given host and predicted to be suspicious based on their characteristics. This approach aims to detect Living off the Land (LotL) attacks, where adversaries use legitimate system binaries (LOLbins) to evade traditional signature-based detection methods. The rule…
