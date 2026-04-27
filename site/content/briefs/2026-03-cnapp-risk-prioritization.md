---
title: CrowdStrike CNAPP Advances with Adversary-Informed Risk Prioritization
slug: 2026-03-cnapp-risk-prioritization
description: CrowdStrike is enhancing its CNAPP capabilities with adversary-informed risk prioritization, application-layer visibility, and improved risk detection to address gaps in cloud security and reduce breach risks.
date: "2026-03-28T09:14:12Z"
severities:
  - medium
actors:
  - LABYRINTH CHOLLIMA and SCATTERED SPIDER
tags:
  - CNAPP
  - cloud-security
  - risk-prioritization
  - threat-intelligence
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
  - title: Detect Overly Permissive Cloud Storage Access
    description: Detects potentially overly permissive access configurations in cloud storage resources that could be exploited by threat actors.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Lateral Movement Through Cloud Instance Credentials
    description: Detects use of stolen or compromised credentials from cloud instances.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.001
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

CrowdStrike is advancing its Cloud Native Application Protection Platform (CNAPP) to provide more effective cloud security. Current CNAPP solutions often lack visibility into business applications, ignore adversary behavior patterns, and create endless triage cycles due to a lack of context. CrowdStrike's enhanced CNAPP capabilities aim to address these limitations by incorporating application-layer visibility, threat intelligence, and automated risk detection. These updates enable…
