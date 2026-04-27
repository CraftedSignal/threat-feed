---
title: CrowdStrike CNAPP Enhanced with Adversary-Informed Risk Prioritization
slug: 2026-03-cnapp-adversary-informed-risk
description: CrowdStrike enhances its CNAPP capabilities by incorporating adversary intelligence for improved risk prioritization, addressing limitations in infrastructure visibility, threat actor behavior analysis, and alert triage.
date: "2026-03-29T00:00:00Z"
severities:
  - medium
actors:
  - LABYRINTH CHOLLIMA, SCATTERED SPIDER
tags:
  - cloud-security
  - cnapp
  - risk-prioritization
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Cloud Account with Excessive Permissions
    description: Detects a cloud account with overly permissive IAM policies, potentially allowing for privilege escalation and lateral movement.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Data Exfiltration via Cloud Storage
    description: Detects data exfiltration attempts by monitoring for large or unusual data transfers to cloud storage services.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

CrowdStrike has enhanced its Cloud Native Application Protection Platform (CNAPP) to provide adversary-informed risk prioritization. Current CNAPP solutions often fall short by focusing solely on infrastructure, ignoring specific adversary behaviors, and generating excessive alerts. This update to CrowdStrike Falcon Cloud Security addresses these gaps by providing visibility into business applications, correlating risks with known adversary tactics (such as those used by LABYRINTH CHOLLIMA and…
