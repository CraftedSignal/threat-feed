---
title: StoatWaffle Malware Used by WaterPlum Actor
slug: 2024-01-stoatwaffle
description: StoatWaffle is malware employed by the WaterPlum threat actor, used for an unknown purpose.
date: "2026-03-19T05:35:27Z"
severities:
  - medium
actors:
  - WaterPlum
tags:
  - stoatwaffle
  - waterplum
  - malware
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rxs0ju/stoatwaffle_malware_used_by_waterplum_%E3%82%BB%E3%82%AD%E3%83%A5%E3%83%AA%E3%83%86%E3%82%A3%E3%83%8A%E3%83%AC%E3%83%83%E3%82%B8/
rules:
  - title: Detect Generic Suspicious Process Creation
    description: Detects suspicious process creations based on command line arguments
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect mshta Execution
    description: Detects the execution of mshta.exe which can be used to execute malicious .hta files.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1218.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The threat brief addresses the StoatWaffle malware associated with the threat actor WaterPlum. Specific details regarding the malware's capabilities, deployment methods, and targeted sectors are currently limited based on the available source material. Further analysis is required to determine the exact scope and impact of StoatWaffle and WaterPlum's operations. Defenders should prioritize gathering additional intelligence on this threat to implement appropriate detection and mitigation…
