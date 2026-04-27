---
title: SOC Analyst Toolkit with Threat Hunting Queries
slug: 2026-03-soc-analyst-hub
description: A free, offline SOC toolkit aimed at Tier 1 analysts includes IR checklists, triage playbooks, and threat hunting guides mapped to MITRE ATT&CK, with Splunk and Elastic queries for threats such as Kerberoasting, Pass-the-Hash, LOLBAS, scheduled task persistence, and C2 on non-standard ports.
date: "2026-03-18T12:00:00Z"
severities:
  - low
tags:
  - soc
  - blueteam
  - threat-hunting
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rw71as/built_a_free_offline_soc_analyst_hub_for_tier_1/
  - https://cross-samuel1.github.io/soc-analyst-hub/
  - https://github.com/cross-samuel1/soc-analyst-hub
ioc_counts:
  url: 2
rules:
  - title: Detect Suspicious Scheduled Task Creation
    description: Detects the creation of scheduled tasks that may be used for persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
  - title: Detect Connections to Non-Standard Ports
    description: Detects network connections to common command and control ports.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A security practitioner has released a free, offline SOC toolkit intended for Tier 1 analysts and those new to blue team operations. This toolkit, contained within a single HTML file, provides resources for incident response, alert triage, threat hunting, and analyst onboarding. Released in March 2026, the toolkit includes interactive IR checklists for common incident types (Phishing, Malware, Brute Force, Data Exfil, Suspicious PowerShell), alert triage playbooks with decision trees, threat…
