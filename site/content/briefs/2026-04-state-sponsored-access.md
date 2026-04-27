---
title: State-Sponsored Actors Leveraging Vulnerabilities and Identity for Persistent Access (2025)
slug: 2026-04-state-sponsored-access
description: In 2025, state-sponsored actors from China, Russia, North Korea, and Iran leveraged vulnerabilities and identity compromise for initial access, focusing on persistence for long-term espionage or disruption.
date: "2026-04-14T13:51:01Z"
severities:
  - high
actors:
  - China, Russia, North Korea, Iran (State-Sponsored)
tags:
  - state-sponsored
  - apt
  - persistence
  - vulnerability-exploitation
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1105
    technique_name: Remote File Copy
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://blog.talosintelligence.com/state-sponsored-threats-different-objectives-similar-access-paths/
rules:
  - title: Detect Web Shell Activity
    description: Detects potential web shell activity through suspicious HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
  - title: Detect Backdoor Installation via Uncommon Process
    description: Detects potential backdoor installations by monitoring for execution of uncommon processes from suspicious locations.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

In 2025, state-sponsored threat actors from China, Russia, North Korea, and Iran exhibited distinct motivations, ranging from espionage and disruption to financial gain and geopolitical influence. Despite these varying objectives, these actors employed similar tactics, techniques, and procedures (TTPs), particularly regarding initial access and persistence. A common thread was the exploitation of both newly disclosed (e.g., ToolShell by China) and long-standing vulnerabilities in networking…
