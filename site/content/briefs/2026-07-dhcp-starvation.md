---
title: Potential DHCP Starvation via High Client MAC Cardinality
slug: 2026-07-dhcp-starvation
description: Attackers utilize DHCP starvation by flooding network segments with DHCP DISCOVER messages containing a high cardinality of distinct client MAC addresses to exhaust the DHCP lease pool, potentially leading to denial of service for legitimate clients and facilitating rogue DHCP server deployment.
date: "2026-07-05T01:27:06Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - network-attack
  - denial-of-service
  - network-security-monitoring
  - impact
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Identifies a burst of DHCP DISCOVER messages with an unusually high number of distinct client hardware addresses observed on the same capture segment within a short window. Attackers flood DISCOVER requests with spoofed or random MAC addresses to exhaust the DHCP lease pool
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1498/
  - https://www.leviathansecurity.com/blog/tunnelvision
  - https://wazuh.com/blog/monitoring-dhcp-starvation-attack-with-suricata-and-wazuh/
---

This threat involves a network-based denial of service attack known as DHCP starvation. Attackers generate an unusually high volume of DHCP DISCOVER messages, each containing a distinct, often spoofed or randomly generated, client hardware (MAC) address. This flood aims to rapidly deplete the legitimate DHCP server's available IP address pool. The attack typically occurs on the same capture segment within a short time window and can leave legitimate network clients unable to obtain or renew IP addresses. This technique is frequently used as a precursor to deploying a rogue DHCP server, allowing attackers to control network configurations for clients and facilitate further malicious activities such as Man-in-the-Middle attacks.

## Attack Chain

1.  **Attacker Pre-computation/Setup**: The attacker prepares specialized tools or scripts capable of rapidly generating DHCP DISCOVER messages.
2.  **Network Access**: The attacker gains network access to the target broadcast segment where DHCP clients communicate with the DHCP server.
3.  **DHCP DISCOVER Flood Initiation**: The attacker initiates a flood of DHCP DISCOVER messages onto the network segment.
4.  **MAC Address Spoofing**: Each DHCP DISCOVER message is crafted with a unique, spoofed, or randomly generated client MAC address to appear as distinct clients.
5.  **DHCP Lease Pool Exhaustion**: The legitimate DHCP server attempts to process these numerous DISCOVER requests by assigning IP addresses and leases to each unique MAC address, rapidly depleting its available IP address pool.
6.  **Denial of Service for Legitimate Clients**: As the DHCP lease pool becomes exhausted, legitimate client devices on the network segment are unable to obtain or renew IP addresses, leading to a denial of service for these devices.
7.  **Rogue DHCP Server Deployment (Potential Follow-up)**: This starvation often serves as a preparatory step, enabling the attacker to deploy a rogue DHCP server that can then offer malicious network configurations (e.g., rogue DNS servers, default gateways) to clients, facilitating further attacks like Man-in-the-Middle.

## Impact

The primary impact of a successful DHCP starvation attack is the denial of service for legitimate network clients, rendering them unable to connect to the network or access resources. This leads to widespread operational disruption across affected segments. If followed by a rogue DHCP server, attackers can redirect traffic, intercept communications, or serve malicious content, leading to data exfiltration, system compromise, and significant financial and reputational damage. While no specific victim count or sectors are mentioned, any organization relying on DHCP for IP address management is vulnerable.

## Recommendation

*   Enable network traffic logging and DHCP message parsing via tools like Packetbeat or similar network monitoring solutions, specifically targeting UDP ports 67/68, to provide the necessary telemetry for detecting DHCP starvation.
*   Review DHCP server logs (e.g., Windows DHCP server logs, ISC DHCPd logs) for signs of IP pool exhaustion, NAK spikes, or lease-denial events that correlate with suspected DHCP starvation attempts.
*   Configure and monitor network devices for rogue DHCP OFFER/ACK activity, potentially using dedicated detection rules for "Multiple DHCP Servers Responding to the Same Transaction" as mentioned in the Elastic guide.
*   Implement DHCP snooping and rate limiting on network access switches to mitigate and prevent DHCP starvation attacks by controlling legitimate DHCP traffic and blocking spoofed or excessive DISCOVER messages.
*   Leverage switch CAM tables (e.g., via SNMP or CLI automation) to identify the physical port and source host associated with any observed high volume of DHCP DISCOVER messages.
