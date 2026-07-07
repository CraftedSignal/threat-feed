---
title: RPC (Remote Procedure Call) Services Exposed to the Internet
slug: 2026-07-rpc-internet-exposure
description: Threat actors frequently exploit internet-exposed Remote Procedure Call (RPC) services, primarily on port TCP/135, as an initial access or backdoor vector, leading to unauthorized system access, internal network compromise, and potentially data exfiltration or ransomware deployment.
date: "2026-07-03T16:01:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - network-traffic
  - initial-access
  - lateral-movement
  - vulnerability
  - misconfiguration
  - network
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: it is frequently targeted and exploited by threat actors as an initial access or backdoor vector.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: frequently targeted and exploited by threat actors as an initial access or backdoor vector.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: ""
    evidence: frequently targeted and exploited by threat actors as an initial access or backdoor vector.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/network/initial_access_rpc_remote_procedure_call_to_the_internet.toml
  - https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
rules:
  - title: RPC (Remote Procedure Call) to the Internet
    description: Detects network events indicating the use of RPC traffic from internal networks to the Internet, which is frequently targeted and exploited as an initial access or backdoor vector. Exposure of RPC services to the Internet should be avoided.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - lateral_movement
    techniques:
      - T1021
      - T1021.003
      - T1190
    data_sources:
      - network_connection
rules_count: 1
---

This threat brief addresses the critical security risk posed by Remote Procedure Call (RPC) services being directly exposed to the Internet. While RPC is a legitimate and common protocol for remote management and resource sharing within internal networks, its direct exposure to external networks is a significant misconfiguration frequently targeted and exploited by threat actors. Attackers leverage this exposure as an initial access vector or to establish persistent backdoors, enabling unauthorized access, lateral movement, and ultimately, network compromise. The provided intelligence highlights that such traffic is a strong indicator of potential exploitation attempts by monitoring specific ports (like TCP/135) and internal-to-external IP ranges. Identifying and mitigating this exposure is crucial for preventing severe security incidents.

## Attack Chain

This brief focuses on detecting a critical security misconfiguration: the exposure of Remote Procedure Call (RPC) services directly to the Internet. The provided intelligence describes RPC to the Internet as a frequently targeted and exploited vector for initial access and backdoor establishment, rather than detailing a specific multi-stage attack campaign. If exploited, the typical sequence of events would involve:

1.  **Internet Scanning**: Threat actors actively scan public IP ranges to identify hosts with exposed RPC services, often targeting TCP port 135 (DCE/RPC Endpoint Mapper).
2.  **Vulnerability Identification**: Once an exposed RPC service is found, attackers attempt to identify specific vulnerabilities or misconfigurations that can be leveraged for unauthorized access or remote code execution.
3.  **Initial Access**: Exploitation of the identified RPC vulnerability grants the attacker initial access to the target system, often achieving privileged execution or a remote shell.
4.  **Backdoor Establishment**: To maintain persistent control, the attacker deploys a backdoor or modifies system configurations to ensure continued access to the compromised machine.
5.  **Internal Reconnaissance**: From the initially compromised host, the attacker performs internal network reconnaissance to map the environment, identify other systems, and search for valuable assets.
6.  **Lateral Movement**: The attacker then attempts to move laterally within the network, potentially exploiting other internal RPC services (like DCOM over SMB) or other vulnerabilities to expand their control and reach their ultimate objectives.
7.  **Objective Achievement**: The final stage involves achieving the attacker's goal, which could range from data exfiltration, deployment of ransomware, or maintaining long-term espionage capabilities.

## Impact

The direct exposure of RPC services to the Internet creates a severe vulnerability that, if exploited, can lead to significant organizational damage. Successful exploitation commonly results in unauthorized access to internal systems, allowing threat actors to gain a foothold within the network. This initial breach can rapidly escalate to broader network compromise, data exfiltration, the deployment of ransomware, or the establishment of long-term espionage capabilities. Without detection and remediation, affected organizations face potential data loss, operational disruption, financial costs from recovery, and reputational damage. The lack of proper segmentation for RPC traffic to the Internet essentially creates an open door for adversaries.

## Recommendation

*   Deploy the Sigma rule provided in this brief to your SIEM/detection platform to detect outbound RPC traffic from internal networks to the Internet.
*   Investigate all alerts generated by the `RPC (Remote Procedure Call) to the Internet` rule to determine the legitimacy and intent of the communication.
*   Review the source IP addresses involved in detected RPC traffic and check for any recent changes or anomalies on those systems.
*   Implement strict network segmentation and firewall rules to prevent RPC traffic (specifically TCP/135 and DCE/RPC) from originating from internal networks and reaching the Internet.
*   Apply necessary patches and updates to all systems that may be exposing RPC services, addressing any known vulnerabilities.
*   Conduct regular vulnerability assessments and penetration tests to identify and remediate internet-facing RPC exposures.
