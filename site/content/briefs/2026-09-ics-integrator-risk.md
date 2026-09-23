---
title: Supply Chain Risk for Critical Infrastructure via ICS Integrators
slug: 2026-09-ics-integrator-risk
description: Foreign threat actors compromised a U.S. industrial automation integrator between March and April 2025 to exfiltrate sensitive SCADA schematics and device details, creating potential pivot points into downstream critical infrastructure networks.
date: "2026-09-23T17:56:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - ics
  - scada
  - espionage
  - ot-security
  - informational
  - threat-intel
  - remote-access
  - intelligence-gathering
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
    evidence: Critical infrastructure owners and operators should action the recommendations in this fact sheet to work with integrators to ensure secure practices and frameworks are put in place to reduce the risk of malicious actors exploiting third-party accesses to compromise critical infrastructure operational environments.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
    evidence: Malicious foreign cyber actors gained access to the network of a U.S. industrial automation solutions company... and created nine .zip files... for presumed exfiltration.
    confidence_band: med
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Malicious foreign cyber actors... created nine .zip files... for presumed exfiltration, including customer SCADA information, ICS device details, and other schematics.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - SOC
    - Asset Management
    - Vendor Risk Management
  immediate_actions:
    - action: Review and audit all active remote access accounts provided to third-party integrators for adherence to least privilege.
      owner: SOC
      due: 72h
      evidence: Critical infrastructure owners and operators should maintain caution when granting third-party ICS integrators high levels of access.
---

CISA and the FBI have issued guidance following the observation of foreign cyber actors compromising a U.S. industrial automation solutions company. Between March and April 2025, attackers gained unauthorized access to the integrator's network, which provides engineering, SCADA programming, and consulting services to power utilities and transportation entities. The threat actors conducted extensive reconnaissance, specifically searching for terms like "customers" and "SCADA," resulting in the creation of nine .zip files containing approximately 800 files for exfiltration. This incident highlights a significant supply chain vulnerability where attackers leverage the trusted access held by third-party integrators to gain intelligence on downstream operational technology (OT) environments. By exfiltrating device details and infrastructure schematics, actors aim to facilitate future disruptive or destructive attacks against the critical infrastructure systems managed by these integrators.

## Attack Chain

1. Initial access gained to a U.S. industrial automation solutions company network by foreign cyber actors.
2. Internal reconnaissance performed to identify high-value targets, specifically searching for customer-related documentation and SCADA system information.
3. Identification of sensitive files including SCADA information, ICS device details, and network schematics.
4. Staging of identified data into compressed .zip archives for streamlined collection.
5. Exfiltration of approximately 800 files from the integrator's environment.
6. Potential future pivot activities leveraging the stolen intelligence to target the networks of power and transportation entities.
7. Final objective of conducting disruptive or destructive operations within the OT environments of critical infrastructure owners and operators.

## Impact

The compromise of a third-party integrator provides malicious actors with high-fidelity intelligence regarding the OT environments of critical infrastructure entities. Successful exfiltration of schematics and device configurations significantly lowers the barrier for attackers to develop targeted exploits. If attackers successfully leverage this intelligence to pivot into operational networks, the potential consequences include large-scale disruption to power grids, transportation systems, and other essential services, posing risks to both equipment and public safety.

## Recommendation

Prioritized actions for critical infrastructure owners and operators:

- Review and enforce the Principle of Least Privilege (PoLP) for all third-party remote access accounts to ensure access is strictly limited to necessary OT systems.
- Audit all remote access routes into the ICS network; implement on-demand (just-in-time) access policies where the operator must proactively approve sessions rather than allowing persistent connections.
- Incorporate strict cybersecurity, patch management, and supply chain requirements into all service agreements and contracts with third-party integrators.
- Request and maintain a comprehensive inventory of all software and hardware components supplied by the integrator, including connection documentation and lifecycle update plans.
- Develop and test manual operation procedures and maintain offline, secure backups of all software required to recover systems in the event of an integrator-related compromise.
