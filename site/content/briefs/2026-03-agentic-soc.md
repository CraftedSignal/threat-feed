---
title: CrowdStrike Agentic MDR and SOC Transformation Services
slug: 2026-03-agentic-soc
description: CrowdStrike introduces agentic MDR and SOC Transformation Services leveraging AI and automation to accelerate breach response and modernize security operations.
date: "2026-03-29T01:41:24Z"
severities:
  - medium
tags:
  - agentic-soc
  - mdr
  - soc
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encryption for Impact
references:
  - https://crowdstrike.com/en-us/blog/crowdstrike-services-and-agentic-mdr-put-the-agentic-soc-in-reach/
rules:
  - title: Detect Falcon Fusion SOAR Execution
    description: Detects the execution of CrowdStrike Falcon Fusion SOAR playbooks, indicating automated response actions.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Processes Leveraging AI Libraries
    description: Detects processes loading AI-related libraries, which could indicate malicious use of AI agents.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - image_load
      - windows
  - title: Detecting SIEM Log Source Onboarding Activity
    description: Detects activity related to log source onboarding, useful for identifying migrations to Next-Gen SIEM
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1518
    data_sources:
      - file_event
      - windows
rules_count: 3
---

CrowdStrike is introducing agentic Managed Detection and Response (MDR) and Security Operations Center (SOC) Transformation Services designed to enhance breach response capabilities by combining machine-speed execution with human expertise. These services aim to address the challenges posed by modern adversaries who leverage AI to evade detection across diverse systems, including endpoints, cloud environments, and third-party platforms. The agentic MDR solution, delivered through Falcon…
