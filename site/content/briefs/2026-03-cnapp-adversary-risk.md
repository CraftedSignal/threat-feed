---
title: CrowdStrike Falcon Cloud Security CNAPP with Adversary-Informed Risk Prioritization
slug: 2026-03-cnapp-adversary-risk
description: CrowdStrike Falcon Cloud Security enhances CNAPP capabilities with application-layer visibility and adversary-informed risk prioritization, enabling security teams to focus on attacker-aligned risks and known threat actors.
date: "2026-03-28T09:35:23Z"
severities:
  - medium
actors:
  - LABYRINTH CHOLLIMA, SCATTERED SPIDER
tags:
  - cloud-security
  - cnaap
  - risk-prioritization
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Potential Cloud Account Compromise via Unusual Region
    description: Detects cloud account activity originating from a geographic region that is not typical for the user, potentially indicating account compromise.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Cloud Resource with Overly Permissive Access
    description: Detects cloud storage resources with overly permissive access, potentially indicating a misconfiguration that could lead to data exposure.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

CrowdStrike has enhanced its Falcon Cloud Security CNAPP (Cloud-Native Application Protection Platform) with new features aimed at improving risk assessment and prioritization. These advancements address limitations in current CNAPP solutions, which often lack visibility into business applications, ignore adversary behavior, and result in endless triage. The new capabilities provide security teams with the context needed to understand cloud risk, prioritize remediation, and accelerate response…
