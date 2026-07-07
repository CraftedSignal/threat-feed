---
title: Detection of Accepted Default Telnet Port Connection
slug: 2026-07-telnet-default-port-connection
description: This brief details the detection of unencrypted Telnet traffic on its default port 23, a legacy protocol commonly used for remote administration but frequently exploited by threat actors for initial access or as a backdoor due to its plain-text nature, which exposes sensitive information and facilitates unauthorized access.
date: "2026-07-03T16:03:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-and-control
  - lateral-movement
  - initial-access
  - telnet
  - network-security
  - detection
  - elastic-rule
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Threat actors frequently exploit Telnet as an initial access or backdoor vector.
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
  - title: Accepted Default Telnet Port Connection
    description: Detects accepted network connections on the default Telnet port (23), which is a clear-text protocol often exploited for initial access or command and control.
    platform: sigma
    severity: high
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

This brief focuses on the inherent risks and detection of unencrypted Telnet traffic, particularly on its default port 23. Telnet, a legacy protocol, is often utilized by system administrators for remote command-line access to older or embedded systems. However, its unencrypted nature poses a significant security risk, as it transmits sensitive information, including usernames and passwords, in plain text. Threat actors frequently target and exploit Telnet services, especially when exposed to the internet, leveraging them as an initial access vector or establishing backdoors into compromised networks. The detection rule aims to flag these high-risk connections, indicating potential unauthorized access attempts or command-and-control communication, thereby necessitating immediate investigation to prevent data exfiltration or broader system compromise. The primary concern is any unexpected or external Telnet activity, which deviates from legitimate, usually internal, administrative workflows.

## Impact

The successful exploitation of Telnet services can lead to severe consequences. Attackers can gain unauthorized remote access to compromised systems, potentially escalating privileges and establishing persistence within the network. Due to Telnet's plain-text communication, any credentials transmitted during a session can be intercepted, leading to further account compromise and lateral movement across the environment. This can result in data exfiltration, deployment of additional malware (e.g., ransomware), or complete control over critical infrastructure. Organizations with Telnet exposed to the internet or widely used internally without proper segmentation face a high risk of initial breach or rapid internal compromise if such connections are not promptly detected and mitigated.

## Recommendation

*   Disable Telnet services on all systems where it is not absolutely essential to eliminate a common attack vector.
*   Replace Telnet with secure, encrypted alternatives like SSH for remote administration across your environment to protect credentials and data in transit.
*   Deploy the Sigma rule "Accepted Default Telnet Port Connection" to your SIEM/detection platform and configure it to alert on any default Telnet port 23 connections, as outlined by the `detection` block.
*   Enable comprehensive network flow logging (e.g., NetFlow, IPFIX) or firewall logs (e.g., logs from Palo Alto Networks, Fortinet, pfSense, SonicWall) to feed your SIEM for correlation with the `logsource` categories identified in the rule.
*   Investigate all alerts generated by the "Accepted Default Telnet Port Connection" rule, prioritizing external connections or those involving critical assets, referring to the `falsepositives` for tuning.
*   Implement strict network segmentation to limit Telnet access to only authorized internal subnets and prevent any exposure to the internet.
