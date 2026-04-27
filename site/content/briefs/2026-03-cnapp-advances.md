---
title: CrowdStrike CNAPP Advances with Adversary-Informed Risk Prioritization
slug: 2026-03-cnapp-advances
description: CrowdStrike's new CNAPP capabilities in Falcon Cloud Security address limitations in cloud risk assessment by providing application layer visibility, attacker-aligned risk prioritization based on threat actor profiles and observed techniques, and configuration change tracking to expedite remediation.
date: "2026-03-28T08:13:07Z"
severities:
  - medium
tags:
  - cloud-security
  - cnapp
  - risk-prioritization
  - threat-intelligence
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070.001
    technique_name: 'Indicator Removal on Host: Clear Windows Event Logs'
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021.002
    technique_name: 'Remote Services: SMB/Windows Admin Shares'
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Overly Permissive Cloud Storage Access
    description: Detects attempts to access cloud storage resources with overly permissive access policies.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1580
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Outbound Connection from Cloud Application
    description: Detects outbound connections from cloud applications to external AI services or unusual destinations.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

CrowdStrike has announced advancements in its Cloud Native Application Protection Platform (CNAPP) within Falcon Cloud Security. This aims to address critical gaps in cloud risk assessment by incorporating application layer visibility, adversary intelligence, and configuration change tracking. With cloud breaches continuing to rise, even with CNAPP adoption, this update seeks to improve proactive security measures. The new capabilities focus on understanding how applications interact with…
