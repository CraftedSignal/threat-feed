---
title: Sandworm Targeted Polish Energy Facility via Private APN Pivot
slug: 2026-08-polish-energy-apn
description: In December 2025, the threat actor Sandworm exploited an internet-facing firewall and a misconfigured cellular router to pivot through a private APN into a Polish energy facility's OT network, resulting in industrial sabotage.
date: "2026-08-10T10:28:24Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Sandworm
  - BlackEnergy
  - Voodoo Bear
  - Seashell Blizzard
  - IRIDIUM
vendors:
  - Fortinet
  - Teltonika
  - Wago
  - Siemens
  - Moxa
  - ABB
  - Schneider Electric
products:
  - VPN and firewall
  - Cellular router
  - Programmable logic controller
  - Serial device server
  - Network switch
  - Variable frequency drive
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The intrusion started on a Fortinet VPN and firewall device located at a wind farm and connected to the internet.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An SSH service running on the device was then used to establish a tunnel.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: The attacker scanned the private APN network and identified a Wago programmable logic controller.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021.004
    technique_name: 'Remote Services: SSH'
    evidence: An SSH service enabled on this controller gave the attacker access to the plant’s operational technology networks.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
    evidence: connected to Siemens PLCs, switched them to ‘stop’ mode, and set a password to prevent operators from changing the controllers’ operating state.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: The attacker then damaged the WAGO controller that had been used as a gateway into the network by corrupting its partition table.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - SOC
    - OT Security Team
  immediate_actions:
    - action: Review edge firewall and VPN device security configurations and restrict management interfaces.
      owner: SOC
      due: 24h
      evidence: Intrusion started on a Fortinet VPN and firewall device.
  mitigation_plan:
    - priority: immediate
      action: Disable unused SSH services on PLCs and industrial network hardware.
      owner: OT Security Team
      addresses: Unauthorized lateral movement via SSH
      evidence: An SSH service enabled on this controller gave the attacker access to the plant’s operational technology networks.
---

In December 2025, threat actors linked to Sandworm conducted a targeted cyberattack against a combined heat and power (CHP) plant in Poland. The attackers successfully sabotaged industrial control systems (ICS), leading to the shutdown of steam turbines and water treatment systems. This incident is notable for the group's novel use of a private Access Point Name (APN) configuration as an attack vector to pivot from a compromise at a wind farm into the operational technology (OT) network of the energy facility. The attackers performed reconnaissance, took control of programmable logic controllers (PLCs), and ultimately bricked hardware to hinder incident response and forensic analysis. This incident occurred alongside a broader campaign targeting approximately 30 energy sites in Poland.

## Attack Chain

1. Initial access was gained via an internet-facing Fortinet VPN and firewall device located at a wind farm.
2. The attackers accessed the admin interface of a Teltonika cellular router connected to the same network as the firewall.
3. An SSH service on the Teltonika router was leveraged to establish an unauthorized tunnel.
4. The tunnel enabled the attackers to pivot into a private APN network managed by the distribution system operator (DSO).
5. The attackers scanned the private APN network, identifying a Wago PLC that acted as a gateway into the CHP plant’s internal OT network.
6. Using SSH access on the Wago PLC, the attackers moved laterally to Siemens PLCs, setting them to 'stop' mode and applying unauthorized passwords to prevent operator intervention.
7. The attackers targeted Moxa network infrastructure and ABB/Schneider Electric variable frequency drives to disable operator access and control.
8. Final objective was achieved through system disruption and permanent destruction (bricking) of hardware to cover tracks and prevent recovery.

## Impact

The attack resulted in the shutdown of steam turbine and water treatment systems, causing a disruption to the cogeneration process at a facility supplying heat to 50,000 residents. While the supply of electricity and heat was not interrupted long-term, the attackers caused permanent hardware damage to several ICS components, requiring physical replacement and logic restoration from backups.

## Recommendation

* Audit all internet-facing VPN and firewall appliances for unauthorized remote access or misconfigured interfaces.
* Restrict access to cellular router administration interfaces using strong authentication and network segmentation.
* Review private APN configurations to ensure that OT networks are not routable from edge devices or external tunnels without strict policy enforcement.
* Implement secure, authenticated access controls for all PLC management interfaces; disable unused SSH services on industrial hardware.
* Monitor for unauthorized SSH tunneling or unusual scanning activity originating from cellular infrastructure within the OT environment.
