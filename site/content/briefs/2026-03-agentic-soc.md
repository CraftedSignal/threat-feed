---
title: CrowdStrike Agentic MDR and SOC Transformation Services
slug: 2026-03-agentic-soc
description: CrowdStrike introduces agentic MDR and SOC Transformation Services to enhance SOC capabilities with AI and automation, emphasizing data foundations, workflows, and governance for improved detection and response across diverse environments.
date: "2026-03-30T06:22:22Z"
severities:
  - medium
tags:
  - agentic-soc
  - ai
  - automation
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://crowdstrike.com/en-us/blog/crowdstrike-services-and-agentic-mdr-put-the-agentic-soc-in-reach/
rules:
  - title: Detect SIEM Log Source Onboarding Activity
    description: Detects activity related to log source onboarding, which is a key step in SIEM modernization and could indicate malicious activity if unauthorized.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1059.001
    data_sources:
      - file_event
      - windows
  - title: Detect Workflow Redesign Script Execution
    description: Detects script execution that is part of a workflow redesign, which attackers could abuse to introduce malicious processes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike has launched its Agentic MDR and SOC Transformation Services in March 2026. These services are designed to help organizations modernize their security operations centers (SOCs) by integrating AI and automation. The core focus is on establishing robust data foundations, optimizing workflows, and implementing governance guardrails to ensure that automation operates safely and consistently. The services aim to address the challenges posed by adversaries who are increasingly leveraging…
