---
title: Detection of AdFind Active Directory Discovery Activity
slug: 2026-10-adfind-reconnaissance
description: AdFind.exe is a legitimate Active Directory query tool frequently repurposed by threat actors for post-exploitation reconnaissance in ransomware and criminal campaigns.
date: "2026-10-07T16:41:36Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - discovery
  - active-directory
  - reconnaissance
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
    evidence: The rule detects discovery-related arguments used by AdFind to enumerate network or domain information.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087.002
    technique_name: ""
    evidence: AdFind is observed querying for person objects to perform account discovery.
    confidence_band: high
references:
  - http://www.joeware.net/freetools/tools/adfind/
  - https://thedfirreport.com/2020/05/08/adfind-recon/
  - https://cloud.google.com/blog/topics/threat-intelligence/tactics-techniques-procedures-associated-with-maze-ransomware-incidents
  - https://cloud.google.com/blog/topics/threat-intelligence/pick-six-intercepting-a-fin6-intrusion
rules:
  - title: Detect AdFind Active Directory Discovery
    description: Detects the execution of AdFind.exe with command-line arguments indicative of Active Directory enumeration.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1016
      - T1087.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma detection rule to monitor for AdFind reconnaissance activity.
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search historical logs for execution of AdFind.exe to establish a baseline of administrative behavior.
      technique_id: T1087
      data_needed:
        - Process creation logs
      priority: medium
      confidence: high
      disposition: hunt_now
---

AdFind is a freely available command-line tool developed by Joeware for querying Active Directory (AD). While intended for administrative purposes, it is heavily leveraged by threat actors for post-exploitation reconnaissance. Threat groups, including those behind Trickbot, Ryuk, Maze, and FIN6 campaigns, utilize AdFind to map domain structures, identify high-value targets, and scope network subnets. Because the tool is dual-use, detection requires distinguishing legitimate administrative usage from anomalous execution, particularly when the process is invoked with common discovery arguments related to computers, user objects, or domain trusts. Defenders must establish baselines for authorized administrative activity to reduce noise when monitoring for unauthorized enumeration.

## Impact

Successful reconnaissance with AdFind provides adversaries with the situational awareness necessary to move laterally through an environment, identify target systems for ransomware deployment, and locate accounts with elevated permissions. This reconnaissance phase is often a precursor to broader network compromise, data exfiltration, or the deployment of ransomware, significantly increasing the probability of a successful high-impact incident.

## Recommendation

- Implement the provided detection logic to identify AdFind execution with discovery-oriented arguments.
- Establish a baseline for authorized administrators who legitimately use AdFind to minimize false positives.
- Review historical process creation logs on systems where this alert triggers to investigate potential earlier stages of an attack chain.
- If a suspicious execution is identified, perform host isolation and initiate credential audits to assess potential compromise of identified accounts.
