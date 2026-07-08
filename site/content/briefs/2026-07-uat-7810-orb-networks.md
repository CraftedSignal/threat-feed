---
title: 'UAT-7810 Expands ORB Networks with New Custom Malware: LONGLEASH, DOGLEASH, and JARLEASH'
slug: 2026-07-uat-7810-orb-networks
description: China-nexus APT actor UAT-7810 is actively expanding its LapDogs Operational Relay Box (ORB) network by exploiting N-day vulnerabilities in Ruckus and ASUS routers to deploy new custom malware families including LONGLEASH, DOGLEASH, and JARLEASH, enabling advanced command and control capabilities for secondary threat actors.
date: "2026-07-07T10:03:15Z"
lastmod: "2026-07-08T09:32:50Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - UAT-7810
exploited: true
cpes:
  - cpe:2.3:o:ruckuswireless:r310_firmware:10.5.1.0.199:*:*:*:*:*:*:*
  - cpe:2.3:o:ruckuswireless:r500_firmware:10.5.1.0.199:*:*:*:*:*:*:*
  - cpe:2.3:o:ruckuswireless:r600_firmware:10.5.1.0.199:*:*:*:*:*:*:*
  - cpe:2.3:o:ruckuswireless:t300_firmware:10.5.1.0.199:*:*:*:*:*:*:*
  - cpe:2.3:o:ruckuswireless:t301n_firmware:10.5.1.0.199:*:*:*:*:*:*:*
  - cpe:2.3:o:ruckuswireless:t301s_firmware:10.5.1.0.199:*:*:*:*:*:*:*
  - cpe:2.3:o:ruckuswireless:scg200_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ruckuswireless:sz-100_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ruckuswireless:sz-300_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ruckuswireless:vsz_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ruckuswireless:zonedirector_1100_firmware:9.10.2.0.130:*:*:*:*:*:*:*
  - cpe:2.3:o:ruckuswireless:zonedirector_1200_firmware:10.2.1.0.218:*:*:*:*:*:*:*
  - cpe:2.3:o:ruckuswireless:zonedirector_3000_firmware:10.2.1.0.218:*:*:*:*:*:*:*
  - cpe:2.3:o:ruckuswireless:zonedirector_5000_firmware:10.0.1.0.151:*:*:*:*:*:*:*
  - cpe:2.3:a:ruckuswireless:ruckus_wireless_admin:*:*:*:*:*:*:*:*
  - cpe:2.3:o:ruckuswireless:smartzone_ap:*:*:*:*:*:*:*:*
  - cpe:2.3:o:commscope:ruckus_smartzone_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:commscope:ruckus_smartzone_firmware:6.1.0.0.935:*:*:*:*:*:*:*
has_poc: true
tags:
  - apt
  - malware
  - backdoor
  - orb-network
  - router-exploitation
  - china-nexus
  - linux
  - embedded
vendors:
  - Ruckus
  - ASUS
products:
  - Ruckus Wireless Routers
  - ASUS AiCloud Routers
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: UAT-7810 primarily exploit known vulnerabilities in unpatched Ruckus wireless routers
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: After compromising a networking device, UAT-7810 deploys a shell script
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Downloads DOGLEASH
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Adds iptables rules to allow TCP traffic to a specific port, on which DOGLEASH binds and listens.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: 'LONGLEASH... setting up the following channels: Reverse shell to C2, Proxy servers for HTTP, DNS, SOCKS, TCP, ICMP, and UDP'
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
    evidence: LONGLEASH also has the capability to act as an intermediate C2 server. It can obtain commands and data from the original C2 and forward to its peers.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: Any TCP data received is then decoded using a hardcoded password string.
    confidence_band: high
cves:
  - id: CVE-2020-22653
    cvss: 9.8
    epss: 0.00436
  - id: CVE-2020-22658
    cvss: 9.8
    epss: 0.00341
  - id: CVE-2023-25717
    cvss: 9.8
    epss: 0.95107
  - id: CVE-2025-2492
    epss: 0.00968
references:
  - https://blog.talosintelligence.com/uat-7810/
  - https://nvd.nist.gov/vuln/detail/CVE-2020-22653
  - https://nvd.nist.gov/vuln/detail/CVE-2020-22658
  - https://nvd.nist.gov/vuln/detail/CVE-2023-25717
  - https://nvd.nist.gov/vuln/detail/CVE-2025-2492
  - https://thehackernews.com/2026/07/china-linked-uat-7810-expands-orb.html
iocs:
  - type: ip
    value: 194.233.92.26
  - type: ip
    value: 217.15.160.247
  - type: ip
    value: 217.15.164.147
  - type: ip
    value: 95.182.100.231
ioc_counts:
  ip: 4
rules:
  - title: Detect Suspicious Iptables Rule Modifications for DOGLEASH
    description: Detects the creation of suspicious iptables rules used by UAT-7810's DOGLEASH malware to allow incoming TCP traffic on compromised Linux-based routers.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1547.006
      - T1562.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
updates:
  - at: "2026-07-08T09:32:50Z"
    level: L2
    summary: poc_available
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/07/china-linked-uat-7810-expands-orb.html
---

Cisco Talos has identified that the China-nexus APT actor UAT-7810 continues to evolve its custom malware arsenal and expand its LapDogs Operational Relay Box (ORB) network. Since 2025, UAT-7810 has been observed exploiting N-day vulnerabilities in unpatched Ruckus wireless routers and, more recently in early 2026, ASUS AiCloud routers, to establish persistent footholds. The group has developed new malware families, including LONGLEASH (an advanced version of SHORTLEASH), DOGLEASH (a C-based backdoor for Linux devices), and JARLEASH (a JAVA-based backdoor). These tools enable UAT-7810 to establish robust command and control, proxy traffic, and create a resilient ORB network. This network is then leveraged by secondary China-nexus APT actors, such as UAT-5918, to conduct their own malicious operations against high-value targets, making the affected devices critical infrastructure for broader APT campaigns.

## Attack Chain

1.  **Initial Access**: UAT-7810 exploits known N-day vulnerabilities (CVE-2020-22653, CVE-2020-22658, CVE-2023-25717, CVE-2025-2492) in unpatched Ruckus wireless routers and ASUS AiCloud routers to gain unauthorized access.
2.  **Execution/Payload Delivery**: A shell script is deployed to the compromised router, acting as an initial dropper or loader.
3.  **Malware Download**: The shell script downloads secondary malware payloads, such as DOGLEASH, LONGLEASH, or JARLEASH, from attacker-controlled servers (e.g., 194.233.92[.]26, 217.15.160[.]247, 217.15.164[.]147, 95.182.100[.]231).
4.  **Persistence/Network Configuration**: The shell script adds `iptables` rules to the compromised Linux-based device, allowing TCP traffic to a specific hardcoded port where DOGLEASH binds and listens for commands.
5.  **Execution**: DOGLEASH (a C-based ELF binary) is executed on the device, binding to its designated port. LONGLEASH (MIPS, ARM, x64 variants) or JARLEASH (JAVA-based) are also executed depending on the target architecture and operational needs.
6.  **Command and Control (C2)**: DOGLEASH listens for incoming TCP data, decodes it, and executes arbitrary shellcode. LONGLEASH, named "ff-agent" internally, establishes reverse shells, HTTP, DNS, SOCKS, TCP, ICMP, and UDP proxy servers, and can act as an intermediate C2 server, forwarding commands. JARLEASH provides file management, FTP, SFTP, and Netcat capabilities.
7.  **Network Establishment**: The compromised router becomes part of the LapDogs Operational Relay Box (ORB) network, providing resilient and covert infrastructure for command and control.
8.  **Impact Operations**: The established ORB network is subsequently leveraged by associated secondary threat actors to conduct their own malicious attacks, potentially involving data exfiltration, further lateral movement, or other objectives against high-value targets.

## Impact

The primary impact of UAT-7810's activities is the establishment and expansion of the LapDogs Operational Relay Box (ORB) network, which serves as critical infrastructure for other China-nexus APTs. Compromised routers, specifically Ruckus wireless and ASUS AiCloud devices, are transformed into C2 nodes and traffic relays, providing anonymity and resilience for subsequent attacks. This infrastructure facilitates a wide range of malicious operations against high-value targets, including government entities, critical infrastructure, and other sensitive organizations, potentially leading to widespread data breaches, espionage, and disruption. The exact number of victims is not specified, but the continuous development of sophisticated custom malware and active exploitation of N-day vulnerabilities indicate a significant, ongoing threat aimed at enabling broad-scale APT operations.

## Recommendation

*   Immediately patch all Ruckus wireless routers and ASUS AiCloud routers against CVE-2020-22653, CVE-2020-22658, CVE-2023-25717, and CVE-2025-2492 to mitigate initial access vectors.
*   Block inbound and outbound connections to the observed C2/payload distribution IP addresses 194.233.92[.]26, 217.15.160[.]247, 217.15.164[.]147, and 95.182.100[.]231 at the network perimeter.
*   Deploy the Sigma rule "Detect Suspicious Iptables Rule Modifications for DOGLEASH" to your SIEM to identify `iptables` modifications indicative of DOGLEASH deployment on Linux-based network devices.
*   Enable comprehensive logging for process creation and command execution on all Linux-based networking devices, specifically focusing on `iptables` commands.
