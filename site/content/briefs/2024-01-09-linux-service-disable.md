---
title: Linux Service Stop and Disable Detection
slug: 2024-01-09-linux-service-disable
description: Attackers may halt or disable security services on Linux systems to evade defenses, maintain persistence, or disrupt operations, detected through the use of utilities like 'systemctl', 'service', and 'chkconfig'.
date: "2024-01-09T14:30:00Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - attack.defense-evasion
  - attack.t1562
  - attack.impact
  - attack.t1489
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
references:
  - https://www.trendmicro.com/pl_pl/research/20/i/the-evolution-of-malicious-shell-scripts.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_services_stop_and_disable.yml
rules:
  - title: Detect Systemctl Service Stop or Disable
    description: Detects the use of systemctl to stop or disable services on Linux systems, potentially indicating an attempt to evade defenses or disrupt operations.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
      - impact
    techniques:
      - T1489
      - T1562
    data_sources:
      - process_creation
      - linux
  - title: Detect Service Command Stop or Disable
    description: Detects the use of the 'service' command to stop or disable services, indicative of potential malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
      - impact
    techniques:
      - T1489
      - T1562
    data_sources:
      - process_creation
      - linux
  - title: Detect Chkconfig Service Manipulation
    description: Detects the usage of chkconfig to disable services, often used for persistence or defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
      - persistence
    techniques:
      - T1562
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

Attackers may attempt to stop or disable services on a compromised Linux system to impair security tools, disrupt operations, or facilitate further malicious activities. This can involve disabling security software, logging mechanisms, or other critical services that could hinder the attacker's objectives. This activity often forms part of a broader attack campaign aimed at maintaining persistence, evading detection, or causing system-wide disruption. The commands `systemctl`, `service`, and…
