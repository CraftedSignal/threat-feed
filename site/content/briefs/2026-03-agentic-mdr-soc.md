---
title: CrowdStrike Agentic MDR and SOC Transformation Services
slug: 2026-03-agentic-mdr-soc
description: CrowdStrike introduces agentic MDR and SOC Transformation Services to enhance breach prevention through machine-speed execution and expert oversight, while SOC Transformation Services aim to modernize security operations by focusing on SIEM, data pipelines, workflows, talent models, and governance.
date: "2026-03-28T09:23:42Z"
severities:
  - medium
tags:
  - agentic-soc
  - mdr
  - soc
  - ai
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-services-and-agentic-mdr-put-the-agentic-soc-in-reach/
rules:
  - title: Detect PowerShell Execution via Command Line
    description: Detects PowerShell execution via command line, commonly used by attackers for various malicious activities.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Persistence via Scheduled Task Creation
    description: Detects the creation of scheduled tasks, which can be used by attackers to establish persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike has announced agentic MDR and SOC Transformation Services to improve the effectiveness of security operations centers (SOCs). The agentic MDR solution is designed to leverage machine-speed execution with expert accountability to stop breaches more efficiently. This involves combining deterministic automation with expert-defined guardrails, adaptive AI agents, and human oversight to ensure rapid and precise responses to threats. SOC Transformation Services aim to modernize the…
