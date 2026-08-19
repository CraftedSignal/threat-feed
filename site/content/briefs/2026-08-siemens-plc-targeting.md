---
title: Active Reconnaissance and Capability Development Against Siemens S7 PLCs
slug: 2026-08-siemens-plc-targeting
description: Threat actors are using AI-assisted scripts and the snap7 library to target Internet-exposed Siemens S7 Series PLCs for reconnaissance and potential operational disruption across critical infrastructure sectors.
date: "2026-08-19T14:29:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ics
  - ot
  - reconnaissance
  - siemens
  - plc
vendors:
  - Siemens
products:
  - S7-200 Series
  - S7-300 Series
  - S7-400 Series
  - S7-1200 Series
  - S7-1500 Series
mitre_ttps:
  - tactic_id: TA0043
    tactic_name: Reconnaissance
    technique_id: T1596.005
    technique_name: Search Open Technical Databases
    evidence: Actors are using Internet scanning services (e.g., Censys, ZoomEye) to identify Internet-exposed or insufficiently segmented Siemens S7 Series PLCs.
    confidence_band: high
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1587.004
    technique_name: 'Develop Capabilities: AI-Generated Exploitation Scripts'
    evidence: Rapidly iterating exploit code through AI-assisted development, lowering technical barriers to ICS attacks.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-231a
action_plan:
  priority: elevated
  owners:
    - SOC
    - OT Security
  immediate_actions:
    - action: Audit network perimeter for Internet-exposed Siemens PLC interfaces.
      owner: OT Security
      due: 24h
      evidence: Ensure PLCs are not accessible from the Internet.
  mitigation_plan:
    - priority: immediate
      action: Remove direct Internet access to PLC assets and enforce VPN or jump host controls.
      owner: IT Operations
      addresses: Internet-exposed PLCs
      evidence: Ensure PLCs are not accessible from the Internet.
---

Threat actors are actively targeting Siemens S7 Series PLCs by leveraging AI-assisted scripting to generate tools for reconnaissance and capability development. By utilizing Internet scanning services to identify exposed devices, the attackers identify PLCs running outdated software or employing default authentication. The threat actors deploy custom Python scripts, which integrate the `snap7.dll` library, to interact with the S7comm protocol. These tools are frequently masqueraded as legitimate OT monitoring solutions to evade detection. The primary objective of this activity is to perform read/write operations on PLC memory, configuration data, and ladder logic, allowing the actors to refine their exploitation techniques and position themselves for future operational impacts. The campaign is notably broad, affecting multiple U.S. critical infrastructure sectors, including Energy, Water, and Critical Manufacturing.

## Attack Chain

1. The actor conducts external reconnaissance using Internet scanning services (e.g., Censys, ZoomEye) to identify internet-facing Siemens S7 Series PLCs [T1596.005].
2. The actor uses AI-assisted development to generate custom scripts that exploit identified vulnerabilities or insecure/default configurations [T1587.004, T1588.007].
3. The actor gains initial access to the PLC by exploiting weak credentials or unconfigured authentication [T1694].
4. The actor deploys custom Python scripts leveraging `snap7.dll` to establish communication with the PLC via the S7comm protocol [T0834].
5. The actor masquerades the custom malicious script as a legitimate OT monitoring or diagnostic tool to avoid detection by security teams [T0849].
6. The actor performs unauthorized read operations on PLC data blocks, registers, and ladder logic to map the industrial process [T0893].
7. The actor conducts potential write operations or modifications to PLC memory to prepare for future operational effects such as process disruption or equipment damage [T0821].

## Impact

Successful compromise of these PLCs poses significant risks to critical infrastructure, including the disruption of industrial processes, degradation of product quality, and the potential for safety incidents by overriding emergency shutdown systems. Furthermore, unauthorized access allows for the theft of proprietary process configurations, potential regulatory compliance violations, and the potential for cascading failures across interconnected operational technology systems.

## Recommendation

* Conduct an inventory of all Siemens S7 Series PLCs and verify their network segmentation; ensure no PLCs are directly accessible from the public Internet.
* Apply all critical security patches and updates provided by the vendor to remediate known vulnerabilities.
* Implement strong, non-default authentication and access controls for all PLC management interfaces.
* Deploy security tooling to monitor the ICS environment for anomalous S7comm protocol traffic and unauthorized remote connection attempts.
* Investigate endpoints for the presence of unauthorized Python scripts or unknown binaries utilizing the `snap7` library.
