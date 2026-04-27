---
title: CrowdStrike CNAPP Enhanced with Adversary-Informed Risk Prioritization
slug: 2026-03-cnapp-advances
description: CrowdStrike has enhanced its CNAPP capabilities by adding application-layer visibility and prioritizing risks based on known adversary tactics, techniques, and procedures (TTPs).
date: "2026-03-28T14:46:06Z"
severities:
  - medium
actors:
  - LABYRINTH CHOLLIMA, SCATTERED SPIDER
tags:
  - cloud-security
  - cnapp
  - threat-intelligence
  - risk-prioritization
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Potential Lateral Movement via API calls
    description: Detects potential lateral movement within a cloud environment by monitoring API calls associated with accessing different compute instances or services.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.007
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Discovery of Cloud Storage Buckets
    description: Detects attempts to discover cloud storage buckets, which could be an attacker mapping the environment.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1526
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

CrowdStrike has advanced its Cloud-Native Application Protection Platform (CNAPP) to address limitations in current cloud security approaches. The enhancements include Application Explorer, which provides application-layer visibility alongside cloud infrastructure context, and adversary intelligence for cloud risks. These updates aim to help organizations understand how applications interact with infrastructure and prioritize risks based on threat actor behavior. Specifically, the CNAPP maps…
