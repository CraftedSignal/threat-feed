---
title: CrowdStrike CNAPP Enhancements Prioritize Adversary-Informed Cloud Risks
slug: 2026-04-cnapp-risk-prioritization
description: CrowdStrike's new CNAPP capabilities enhance cloud risk assessment by incorporating application-layer visibility, adversary intelligence, and configuration change tracking, enabling security teams to prioritize remediation based on real-world threat actor behavior such as LABYRINTH CHOLLIMA and SCATTERED SPIDER.
date: "2026-03-30T09:13:17Z"
severities:
  - high
actors:
  - LABYRINTH CHOLLIMA, SCATTERED SPIDER
tags:
  - cloud-security
  - cnapp
  - risk-prioritization
  - threat-intelligence
  - adversary-emulation
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1530
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1570
    technique_name: Lateral Tool Transfer
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Overly Permissive Cloud Storage Access
    description: Detects overly permissive access configurations on cloud storage services, which can be exploited for initial access and data exfiltration.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Shadow AI LLM Usage
    description: Detects applications using external Large Language Models (LLMs) that may not be approved or monitored, leading to potential data exposure.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1114.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CrowdStrike has enhanced its Cloud Native Application Protection Platform (CNAPP) with new features designed to address limitations in current cloud risk assessment methodologies. These enhancements, released in March 2026, focus on providing comprehensive visibility, intelligent risk prioritization, and actionable insights. The key features include Application Explorer, which provides application-layer visibility, and adversary intelligence integration, which prioritizes risks based on the…
