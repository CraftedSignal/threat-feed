---
title: CrowdStrike Falcon Cloud Security Introduces Adversary-Informed Risk Prioritization
slug: 2026-03-cnapp-risk-prioritization
description: CrowdStrike's Falcon Cloud Security enhances CNAPP capabilities by introducing adversary-informed risk prioritization, application layer visibility, and root cause analysis of configuration changes, enabling security teams to better understand and remediate cloud risks.
date: "2026-03-28T09:26:44Z"
severities:
  - medium
actors:
  - LABYRINTH CHOLLIMA and SCATTERED SPIDER
tags:
  - cloud
  - cnapp
  - risk-prioritization
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Anomalous Access to Cloud Storage Resources
    description: Detects potentially malicious access to cloud storage resources based on deviations from established access patterns.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Cloud Resource Enumeration by Known Threat Actors
    description: Detects potential cloud resource enumeration activities associated with known threat actors.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

CrowdStrike Falcon Cloud Security has introduced new Cloud Native Application Protection Platform (CNAPP) capabilities focused on improving risk assessment and remediation in cloud environments. The updates address limitations such as lack of application layer visibility, ignoring adversary behavior, and difficulty in tracing the origin of exposures. Falcon Cloud Security now incorporates Application Explorer, providing application-layer visibility, and adversary intelligence, aligning risk…
