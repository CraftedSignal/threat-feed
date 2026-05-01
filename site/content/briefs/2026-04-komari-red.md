---
title: Komari Agent Abused as SYSTEM-Level Backdoor
slug: 2026-04-komari-red
description: Threat actors are abusing the Komari monitoring agent, a project hosted on GitHub, as a SYSTEM-level backdoor following initial access through compromised VPN credentials and lateral movement via Impacket.
date: "2026-04-30T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - komari
  - backdoor
  - nssm
  - github
  - rat
  - reverse shell
vendors:
  - Microsoft
  - Fortinet
  - GitHub
products:
  - Defender
  - FortiGate
  - komari-agent
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1572
    technique_name: Application Layer Protocol
references:
  - https://www.huntress.com/blog/komari-c2-agent-abuse
iocs:
  - type: ip
    value: 45.153.34.132
  - type: domain
    value: VMHeaven.io
ioc_counts:
  domain: 1
  ip: 1
rules:
  - title: Detect Komari Agent Installation via PowerShell
    description: Detects the execution of PowerShell commands used to download and install the Komari agent from GitHub.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.001
      - T1572
    data_sources:
      - process_creation
      - windows
  - title: Detect NSSM Installing Windows Update Service
    description: Detects the use of NSSM to install a service named 'Windows Update Service', a common tactic used to disguise malicious services.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Huntress discovered threat actors leveraging the Komari monitoring agent as a SYSTEM-level backdoor within a partner environment. Komari, a Go-based project on GitHub with over 4,000 stars, is designed as a remote-control and monitoring tool. This incident marks a publicly documented case of Komari being abused in a real-world intrusion. The attackers compromised VPN credentials to gain initial access before deploying the Komari agent as a persistent backdoor. Komari inherently functions as a command-and-control (C2) channel, with features enabled by default. The threat actor installed Komari as a Windows service named "Windows Update Service" using NSSM, directly from the official GitHub repository, which avoided the need for attacker-controlled staging infrastructure. The initial discovery occurred on April 16, 2026.

## Attack Chain

1.  **Initial Access:** The attacker establishes an SSLVPN session on a FortiGate device from IP address 45.153.34[.]132, authenticating as a legitimate user, [User 1].
2.  **Internal Reconnaissance:** After establishing the VPN connection, the attacker's workstation, identified as VM8514, begins enumerating the internal network from the tunnel IP 10.212.134[.]200.
3.  **Lateral Movement:** Using Impacket's smbexec.py, the attacker enables Remote Desktop Protocol (RDP) on the target workstation, [REDACTED-WRKSTN].
4.  **RDP Access:** The attacker establishes an interactive RDP session to [REDACTED-WRKSTN].
5.  **Persistence - Service Creation:** The attacker uses the Non-Sucking Service Manager (NSSM) to install the Komari agent as a persistent Windows service named "Windows Update Service".
6.  **Agent Download:** The Komari agent is downloaded from raw.githubusercontent[.]com/komari-monitor/komari-agent using a PowerShell one-liner executed directly on the system.
7.  **Command and Control:** The Komari agent establishes a persistent WebSocket connection to its server, allowing the attacker to execute arbitrary commands (PowerShell/sh) and initiate interactive PTY reverse shell sessions.
8.  **Maintain Access & Execute:** The attacker maintains SYSTEM-level access via the persistent Komari agent, enabling ongoing remote command execution and control over the compromised workstation.

## Impact

This attack demonstrates how readily available monitoring tools can be weaponized for malicious purposes. A single compromised account led to the establishment of a SYSTEM-level backdoor on a critical workstation. This could result in data exfiltration, further lateral movement within the network, and potentially ransomware deployment. Microsoft Defender quarantined an earlier registry hive dumping attempt, preventing further data compromise. The number of affected organizations is currently unknown, but any organization using the Komari agent without proper security controls is potentially at risk.

## Recommendation

*   Monitor FortiGate logs for SSLVPN sessions originating from suspicious IP addresses (45.153.34[.]132) and unusual ASN's (ASN 51396) to detect potentially compromised credentials.
*   Implement the Sigma rule "Detect Komari Agent Installation via PowerShell" to identify installations of the Komari agent.
*   Monitor process creation events for the execution of `nssm.exe` installing a service named "Windows Update Service" to detect suspicious service installations.
*   Block the domain raw.githubusercontent[.]com at the DNS resolver or web proxy to prevent the downloading of malicious tools and payloads.
