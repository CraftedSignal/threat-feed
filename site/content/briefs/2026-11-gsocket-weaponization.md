---
brief_id: brief-2026-11-11-gsocket-weaponization
event_id: brief-2026-11-11-gsocket-weaponization
revision: 1
activity_at: "2026-11-11T21:35:25Z"
title: Threat actors weaponizing GSocket for persistent C2 on Linux servers
slug: 2026-11-gsocket-weaponization
description: Threat actors are increasingly deploying the legitimate GSocket tool on compromised Linux servers to maintain persistent, encrypted remote access that survives the remediation of initial RCE vulnerabilities.
date: "2026-11-11T21:35:25Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Content reviewed and formatted according to requirements.
tags:
  - c2
  - linux
  - gsocket
  - persistence
  - persistence-mechanism
products:
  - PHP
  - Apache HTTP Server
  - cPanel
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Threat actors exploited internet-facing web applications and used curl to download and execute a remote script.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: Threat actors exploited internet-facing web applications and used curl to download and execute a remote script.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: The deployment script can rename the process, stage files in memory-backed directories, and install persistence that survives a reboot.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Web Protocols
    evidence: The host and the operator each connect outbound to the Global Socket Relay Network, which pairs the two sessions over an end-to-end encrypted channel.
    confidence_band: high
references:
  - https://www.microsoft.com/en-us/security/blog/2026/11/11/global-socket-how-threat-actors-weaponizing-gsocket-stealthy-c2/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Search for process execution from /dev/shm or other temporary directories
      technique_id: T1059.004
      data_needed:
        - Process creation events including command line and file path
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The script profiled the host, selected a GSocket client matching the system architecture, staged it in writable or memory-backed paths such as /dev/shm.
    - lead: Monitor for anomalous outbound network traffic to public relays
      technique_id: T1071.001
      data_needed:
        - Network connection logs (Netflow or firewall logs)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The host and the operator each connect outbound to the Global Socket Relay Network.
---

Threat actors are leveraging GSocket, an open-source remote access tool, to maintain persistent, encrypted command-and-control (C2) channels on compromised Linux systems. This technique allows attackers to retain access even after the initial entry-point vulnerability (such as a web application RCE) has been patched. GSocket operates by establishing outbound connections to a public Global Socket Relay Network, bypassing traditional inbound firewall rules and eliminating the need for attacker-controlled C2 infrastructure.

## Attack Chain
1. Initial Access: Threat actors exploit a remote code execution (RCE) vulnerability in an internet-facing application (e.g., PHP-based applications, cPanel, or Apache).
2. Profiling: The attacker executes commands to profile the system architecture and environment.
3. Tool Transfer: Using curl or similar utilities, the attacker downloads a GSocket deployment script.
4. Staging: The script stages the GSocket binary in temporary or memory-backed directories such as /dev/shm to conceal the file.
5. Execution: The GSocket client is executed, establishing an encrypted outbound connection to the Global Socket Relay Network.
6. C2 Establishment: The relay bridges the connection between the host and the operator, allowing for persistent, interactive access.
7. Persistence: The attacker installs persistent mechanisms to survive system reboots.

## Impact
This technique enables persistent post-compromise access that remains active after the original vulnerability is remediated. The use of a public relay network makes it difficult for defenders to identify malicious activity based solely on traditional IP or domain-based egress blocking.

## Recommendation
- Implement egress filtering to restrict unauthorized outbound connections to known public relay networks.
- Monitor for unauthorized execution of binaries from temporary locations such as /dev/shm.
- Audit for suspicious process names and persistence mechanisms commonly associated with remote access tools.
- Treat the discovery of GSocket on a host as a sign of a persistent compromise, necessitating deeper incident response beyond simply patching the initial entry-point.
