---
title: Accepted Default Telnet Port Connection
slug: 2026-07-accepted-default-telnet-port-connection
description: This threat brief details how threat actors exploit the insecure Telnet protocol on its default port 23 for initial access, lateral movement, and command and control, leveraging its unencrypted nature to compromise systems and exfiltrate data, emphasizing the need for robust detection and mitigation strategies.
date: "2026-07-17T14:42:38Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - telnet
  - network-security
  - remote-access
  - plain-text
  - initial-access
  - lateral-movement
  - command-and-control
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Telnet is commonly used by system administrators to remotely control older or embedded systems using the command line shell.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: Telnet is commonly used by system administrators to remotely control older or embedded systems using the command line shell.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: It should almost never be directly exposed to the Internet, as it is frequently targeted and exploited by threat actors as an initial access or backdoor vector.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It should almost never be directly exposed to the Internet, as it is frequently targeted and exploited by threat actors as an initial access or backdoor vector.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/network/command_and_control_accepted_default_telnet_port_connection.toml
rules:
  - title: Detect Accepted Default Telnet Port Connection
    description: Detects established network connections on the default Telnet port (TCP/23), which is often used by threat actors for initial access or command and control due to its unencrypted nature. This rule filters out denied or terminated connections.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - initial_access
      - lateral_movement
    techniques:
      - T1021
      - T1071
      - T1133
      - T1190
    data_sources:
      - network_connection
rules_count: 1
---

This brief describes the risk associated with unencrypted Telnet connections, commonly targeted by threat actors for initial access and command and control. Telnet, an outdated protocol for remote command-line access on TCP port 23, transmits data in plain text, making it highly vulnerable to eavesdropping and credential theft. Attackers frequently exploit Telnet to gain unauthorized access to older or embedded systems, establishing backdoors, or moving laterally within networks. The detection rule focuses on identifying established Telnet sessions, which can signal a compromise if observed outside of legitimate, tightly controlled legacy administrative workflows. Given its inherent insecurity, any observed Telnet activity, particularly from unusual sources or destinations, warrants immediate investigation to prevent data exposure or system takeover.

## Attack Chain

1. **Reconnaissance**: Threat actors scan internet-facing systems or conduct internal network reconnaissance to identify devices with Telnet services exposed on TCP port 23.
2. **Vulnerability Exploitation / Credential Brute Force**: Attackers attempt to exploit known vulnerabilities in legacy Telnet daemons or perform credential stuffing and brute-force attacks against Telnet login prompts, leveraging default, weak, or harvested credentials.
3. **Initial Access**: Successful authentication or exploitation grants the attacker remote shell access to the target system via the unencrypted Telnet protocol.
4. **Command Execution**: The attacker utilizes the established Telnet session to execute arbitrary commands, enumerate system configurations, gather information, and assess the environment.
5. **Persistence**: To maintain access, the attacker establishes more robust persistence mechanisms, such as installing backdoors, creating new user accounts, or modifying startup scripts, which may or may not rely on continued Telnet access.
6. **Lateral Movement**: Using credentials or information obtained from the compromised system, the attacker initiates new Telnet connections (or other remote services) to pivot to additional systems within the internal network.
7. **Objective Achievement**: The attacker achieves their final objectives, which can include data exfiltration, deployment of ransomware, or further system compromise, potentially using the unencrypted Telnet connection for command and control or data transfer.

## Impact

The successful exploitation of Telnet can lead to severe consequences, including complete system compromise, unauthorized data access, and exfiltration of sensitive information due to the protocol's lack of encryption. Attackers can gain administrative control over targeted systems, install malware, or use the compromised device as a pivot point for further lateral movement within the network. This exposes organizations to significant risks of data breaches, operational disruption, and regulatory non-compliance. While specific victim counts are not available from this detection rule, any organization maintaining internet-exposed or internally accessible Telnet services is vulnerable to these attacks.

## Recommendation

* Deploy the Sigma rule "Detect Accepted Default Telnet Port Connection" to your SIEM and tune for your environment.
* Ensure comprehensive network connection logging is enabled on firewalls, network devices, and endpoints to capture events on TCP port 23.
* Disable Telnet services on all devices, especially those exposed to the internet, as it transmits data in plain text.
* Replace Telnet with secure alternatives like SSH for all remote administration tasks to ensure encrypted communication.
* Implement network segmentation to restrict Telnet access to only strictly necessary internal systems, limiting potential lateral movement paths.
* Review and audit all legacy systems and IoT devices for active Telnet services and implement compensating controls or decommissioning plans.
