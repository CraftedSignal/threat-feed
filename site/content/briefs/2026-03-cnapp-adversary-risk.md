---
title: CrowdStrike CNAPP Enhanced with Adversary-Informed Risk Prioritization
slug: 2026-03-cnapp-adversary-risk
description: CrowdStrike enhances its CNAPP by incorporating adversary-informed risk prioritization, including application-layer analysis and correlation of cloud risks with threat actor profiles like LABYRINTH CHOLLIMA and SCATTERED SPIDER, to enable better risk understanding and remediation.
date: "2026-03-30T06:24:43Z"
severities:
  - medium
actors:
  - LABYRINTH CHOLLIMA, SCATTERED SPIDER
tags:
  - cloud-security
  - cnapp
  - risk-prioritization
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
  - title: Detect Cloud Resource Access by Uncommon Process
    description: Detects processes not normally associated with cloud resource access attempting to connect to cloud storage or compute services, indicating potential lateral movement or privilege escalation
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.007
    data_sources:
      - network_connection
      - windows|linux|macos
  - title: Detect Cloud Instance Metadata API Access Attempt
    description: Detects attempts to access cloud instance metadata API from outside the instance, which could indicate credential harvesting or lateral movement.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.005
    data_sources:
      - network_connection
      - windows|linux|macos
rules_count: 2
---

CrowdStrike has announced advancements to its Cloud-Native Application Protection Platform (CNAPP) with the introduction of adversary-informed risk prioritization. This enhancement addresses limitations in current CNAPP solutions, which often lack visibility into business applications, ignore adversary behavior, and result in endless triage. The new capabilities in CrowdStrike Falcon Cloud Security include Application Explorer, which unifies application-layer visibility with cloud…
