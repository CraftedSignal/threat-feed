---
title: CrowdStrike CNAPP Enhancements Prioritize Risk Based on Adversary Behavior
slug: 2026-03-cnapp-adversary-prioritization
description: CrowdStrike's CNAPP enhancements prioritize cloud risk based on adversary behavior, correlating application insights with cloud infrastructure telemetry to identify and address critical exposures targeted by specific threat actors like LABYRINTH CHOLLIMA and SCATTERED SPIDER.
date: "2026-03-29T07:19:13Z"
severities:
  - high
actors:
  - LABYRINTH CHOLLIMA, SCATTERED SPIDER
tags:
  - cloud-security
  - cnapp
  - threat-intelligence
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
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
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Cloud Infrastructure Misconfiguration Leading to Potential Data Access
    description: Detects overly permissive access to storage resources in cloud environments, potentially exposing sensitive data.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Shadow AI Activity via LLM Usage
    description: Detects unauthorized usage of external Large Language Models (LLMs) from cloud applications, indicating potential shadow AI activity.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - network_connection
      - proxy
rules_count: 2
---

CrowdStrike has enhanced its Cloud Native Application Protection Platform (CNAPP) to prioritize cloud risks based on real-world adversary behavior, addressing limitations in traditional CNAPP solutions. These improvements correlate application-layer visibility with cloud infrastructure context, enabling security teams to understand how applications interact with services, access data, use credentials, and integrate AI components. Falcon Cloud Security maps cloud risks to known adversary…
