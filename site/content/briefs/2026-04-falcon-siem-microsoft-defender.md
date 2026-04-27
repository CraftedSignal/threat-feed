---
title: CrowdStrike Falcon SIEM Integration with Microsoft Defender
slug: 2026-04-falcon-siem-microsoft-defender
description: CrowdStrike's Falcon Next-Gen SIEM expands to support third-party EDR solutions, beginning with Microsoft Defender, to unify detection, investigation, and response without requiring the Falcon sensor and modernize security operations.
date: "2026-03-28T22:14:01Z"
severities:
  - medium
tags:
  - siem
  - edr
  - integration
  - microsoft-defender
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
references:
  - https://www.crowdstrike.com/en-us/blog/falcon-next-gen-siem-supports-third-party-edr-tools-starting-with-microsoft-defender/
rules:
  - title: Detect Suspicious Process Creation via Microsoft Defender Telemetry
    description: Detects suspicious process creations that may indicate post-exploitation activity based on Microsoft Defender Telemetry ingested into CrowdStrike Falcon SIEM.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detecting Data Transformation via Falcon Onum
    description: Detects alterations to telemetry data at the point of ingestion using Falcon Onum.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CrowdStrike is expanding its Falcon Next-Gen SIEM to incorporate third-party EDR solutions, starting with Microsoft Defender. This integration aims to allow organizations to modernize their SOC without replacing existing endpoint agents, addressing the issue of fragmented security systems. Modern attacks exploit gaps across endpoint, identity, network, and cloud environments, forcing security teams to investigate across disparate systems. Falcon Next-Gen SIEM combines index-free search…
