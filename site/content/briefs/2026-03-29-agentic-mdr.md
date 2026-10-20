---
brief_id: brief-2026-03-29-agentic-mdr
event_id: brief-2026-03-29-agentic-mdr
revision: 2
activity_at: "2026-03-29T07:07:39Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:9d39d0d5fb73598cdfcd1a27bd5850ebe4bb689d4543f611bad0af53929596bf
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: CrowdStrike Agentic MDR and SOC Transformation Services
slug: 2026-03-29-agentic-mdr
description: CrowdStrike introduces agentic MDR and SOC Transformation Services to provide a pragmatic path to operationalizing an agentic SOC, combining machine speed execution with expert human judgment to combat modern breaches.
date: "2026-03-29T07:07:39Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
tags:
  - agentic-soc
  - mdr
  - soc-transformation
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-services-and-agentic-mdr-put-the-agentic-soc-in-reach/
rules:
  - title: Detecting Potential Lateral Movement via Uncommon Process Execution
    description: This rule detects processes that are not typically seen executing on a system, which could indicate lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021
    data_sources:
      - process_creation
      - windows
  - title: SIEM Log Source Onboarding Activity
    description: Detects log source onboarding activity which is related to Next-Gen SIEM deployment
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CrowdStrike has announced new Agentic MDR and SOC Transformation Services designed to help organizations evolve towards an "agentic SOC" model. This approach aims to address the increasing speed and sophistication of modern attacks, where adversaries leverage AI and operate across diverse environments, including endpoints, identities, cloud infrastructure, and third-party systems. The core concept involves combining machine-speed execution with expert human oversight to ensure automation is governed effectively. The agentic MDR is delivered by CrowdStrike Falcon Complete and combines deterministic automation, adaptive AI agents and elite human accountability. SOC Transformation Services help organizations establish the foundational operating conditions required for agentic SOC operations and take the initial steps toward agentic execution. These services focus on modernizing SIEM, data pipelines, workflows, talent models, and governance to enable safer and deliberate evolution of security operations.

## Attack Chain

While the document doesn't explicitly detail an attack chain, it provides context for responding to one. Presume the following scenario:

1.  **Initial Access:** An adversary gains initial access through a compromised user account or a vulnerability in a public-facing application.
2.  **Lateral Movement:** The adversary uses stolen credentials or exploits system vulnerabilities to move laterally within the network.
3.  **Privilege Escalation:** The attacker escalates privileges to gain administrative control over critical systems.
4.  **Data Collection:** The adversary collects sensitive data, such as customer information, financial records, or intellectual property.
5.  **Exfiltration:** Stolen data is exfiltrated from the network to an external location controlled by the attacker.
6.  **Impact:** The adversary encrypts systems, disrupts operations, or publicly releases stolen data.
7.  **Response:** Falcon Complete delivers scaled automation through CrowdStrike Falcon® Fusion SOAR and proprietary tooling to execute expert-engineered response playbooks for known threats, with a median time to contain of 1 minute.
8.  **Remediation:** Elite CrowdStrike analysts orchestrate execution end-to-end, validating response actions, and retaining authority over novel or high-impact threats.

## Impact

The attack scenario outlined above could lead to significant financial losses, reputational damage, legal liabilities, and operational disruptions. The introduction of agentic MDR and SOC Transformation Services aims to minimize the impact of successful breaches. By improving detection and response times, these services can limit the scope and severity of attacks, reducing the overall cost and disruption to the organization. The document highlights the increasing speed of attacks, with breakout times measured in seconds, emphasizing the need for rapid and automated response capabilities.

## Recommendation

*   Evaluate CrowdStrike Falcon Next-Gen SIEM for SIEM modernization and migration planning (see: "SIEM modernization and migration planning to CrowdStrike Falcon® Next-Gen SIEM").
*   Assess and modernize detection and response workflows to align with team structure and business risk tolerance (see: "Workflow redesign for triage, escalation, containment, and recovery, aligned to team structure, staffing model, and business risk tolerance").
*   Implement prioritized detection rules and AI use case development for accelerated detection and automation (see: "Detection engineering and automation acceleration, including prioritized detection rules, AI use case development, and guardrails for safe response actions").
*   Ensure you have defined guardrails in place for response actions to ensure that any automation operates safely, consistently, and accountably (see overview)
