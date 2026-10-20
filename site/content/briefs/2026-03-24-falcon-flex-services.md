---
brief_id: brief-2026-03-24-falcon-flex-services
event_id: brief-2026-03-24-falcon-flex-services
revision: 2
activity_at: "2026-03-24T00:00:00Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:a9675cc857482951bd4e8d5b816dd9d18c2bc0202575687e610f5de7ca8d2373
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: CrowdStrike Flex for Services Enhancements
slug: 2026-03-24-falcon-flex-services
description: CrowdStrike is expanding its Falcon Flex model to include cybersecurity services, offering organizations greater flexibility and faster response times to modern threats through a consumption-based approach.
date: "2026-03-24T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
tags:
  - incident-response
  - security-services
  - falcon-flex
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1560
    technique_name: Archive Collected Data
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-extends-the-falcon-flex-model-to-services/
rules:
  - title: Detect First Time PowerShell Script Block Logging Enablement
    description: Detects the initial enabling of PowerShell Script Block Logging, potentially indicating attacker preparation activities during incident response or threat hunting.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Detect CrowdStrike Falcon Sensor Installation
    description: Detects the installation of the CrowdStrike Falcon sensor based on process creation events, useful for tracking endpoint protection deployments or unauthorized installations.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike is extending the Falcon Flex model, previously applied to its platform, to its expert-led cybersecurity services. This enhancement, announced in March 2026, aims to provide organizations with flexible and rapid access to incident response, proactive security services, advisory, platform services, and training. A key component of this expansion is the Zero Dollar Flex Fund, which offers qualifying new customers 200 hours of CrowdStrike Services at no initial cost, including 160 hours for incident response and 40 hours for proactive services. This initiative is designed to lower the barrier for organizations seeking expert support before making broader platform commitments, aligning services consumption with actual security needs and enabling faster response times to evolving cyber threats.

## Attack Chain

This brief focuses on service offerings and doesn't describe a specific attack chain. However, it facilitates faster incident response, which would be relevant after these stages of an attack:

1.  **Initial Access:** An attacker gains initial access to a network (e.g., via phishing).
2.  **Execution:** The attacker executes malicious code on the compromised system.
3.  **Persistence:** The attacker establishes persistence to maintain access.
4.  **Privilege Escalation:** The attacker escalates privileges to gain higher-level control.
5.  **Lateral Movement:** The attacker moves laterally to other systems within the network.
6.  **Command and Control:** The attacker establishes a command and control channel to remotely control the compromised systems.
7.  **Impact:** The attacker achieves their objectives (e.g., data exfiltration, ransomware deployment).
8. **Incident Response Engagement:** Organization uses CrowdStrike's Flex for Services to rapidly engage incident response expertise to contain and remediate the attack.

## Impact

The primary impact of this announcement is improved incident response readiness and faster access to cybersecurity expertise. By reducing procurement friction and providing pre-arranged incident response coverage, organizations can respond more effectively to security incidents. The Zero Dollar Flex Fund aims to lower the barrier to entry for organizations seeking expert support, particularly those that want to assess their readiness and improve their defenses before making a broader platform commitment. This can lead to reduced downtime, minimized data loss, and improved overall security posture.

## Recommendation

*   Evaluate your current incident response plan and identify gaps in coverage (reference: "CrowdStrike Flex for Services").
*   If you are a new CrowdStrike services customer, explore eligibility for the Zero Dollar Flex Fund to gain immediate access to incident response and proactive services (reference: "Zero Dollar Flex Fund").
*   Review CrowdStrike's service offerings to determine which services align with your organization's needs, considering incident response, proactive security assessments, and training (reference: "CrowdStrike Services").
* Evaluate existing security services contracts for flexibility and responsiveness compared to the Falcon Flex model (reference: Falcon Flex model).
