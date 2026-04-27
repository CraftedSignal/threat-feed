---
title: CrowdStrike CNAPP Enhancements for Adversary-Informed Risk Prioritization
slug: 2026-03-crowdstrike-cnapp
description: CrowdStrike's new CNAPP capabilities, including Application Explorer and Adversary Intelligence, enable security teams to prioritize cloud risks based on application context and known adversary behaviors, such as those of LABYRINTH CHOLLIMA and SCATTERED SPIDER, improving remediation efforts.
date: "2026-03-28T08:29:13Z"
severities:
  - medium
tags:
  - cloud-security
  - cnapp
  - threat-intelligence
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Potential Lateral Movement via New Process Execution in Cloud Environments
    description: Detects potential lateral movement attempts by identifying new process executions within cloud environments that are not part of the standard operating procedures.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021
    data_sources:
      - process_creation
      - linux
  - title: Detect AI Application Discovery via Network Connection to LLMs
    description: Detects potential AI application discovery by identifying network connections to known Large Language Model (LLM) services from cloud instances, indicating possible Shadow AI usage.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1518
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

CrowdStrike has enhanced its Cloud Native Application Protection Platform (CNAPP) with new capabilities designed to bridge critical gaps in cloud security. These enhancements aim to provide security teams with a more comprehensive understanding of cloud risks and to enable better-prioritized remediation efforts. The key additions include Application Explorer, which offers visibility into how business applications interact with cloud infrastructure, and Adversary Intelligence for Cloud Risks…
