---
brief_id: brief-2026-11-04-dhcp-starvation
event_id: brief-2026-11-04-dhcp-starvation
revision: 1
activity_at: "2026-11-04T03:42:07Z"
title: Potential DHCP Starvation via High Client MAC Cardinality
slug: 2026-11-dhcp-starvation
description: Adversaries may perform DHCP starvation by flooding network segments with DHCP DISCOVER messages containing spoofed or random MAC addresses, effectively exhausting the DHCP lease pool and creating a prerequisite for rogue DHCP server attacks.
date: "2026-11-04T03:42:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "5"
  rating: A5
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against Elastic detection rule documentation.
tags:
  - impact
  - network-security
  - dhcp
  - denial-of-service
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    subtechnique_id: T1498.001
    subtechnique_name: Direct Network Flood
    evidence: Attackers flood DISCOVER requests with spoofed or random MAC addresses to exhaust the DHCP lease pool, often as a precursor to deploying a rogue DHCP server.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/network/impact_dhcp_starvation_high_client_mac_cardinality.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Network Operations
  immediate_actions:
    - action: Deploy rate limiting and DHCP snooping on network access switches.
      owner: Network Operations
      due: 72h
      evidence: DHCP starvation mitigation best practices.
  hunt_leads:
    - lead: Identify bursts of DHCP DISCOVER traffic with high client MAC cardinality on monitored VLANs.
      technique_id: T1498.001
      data_needed:
        - Network Packet Capture data
        - DHCP server logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: DHCP starvation floods a segment with DISCOVER messages that use many distinct client hardware addresses.
  mitigation_plan:
    - priority: immediate
      action: Enable DHCP snooping on all access switches.
      owner: Network Operations
      addresses: DHCP Starvation
      evidence: Enable or verify DHCP snooping and rate limits on the affected access switches.
---

DHCP starvation is a denial-of-service technique targeting the availability of network addresses on a local segment. By transmitting a high volume of DHCP DISCOVER requests with distinct or spoofed client hardware addresses, an attacker can consume all available addresses in a DHCP server's scope. This often precedes the deployment of a rogue DHCP server to perform man-in-the-middle attacks. Detection requires monitoring raw packet captures for high cardinality of unique MAC addresses in DHCP DISCOVER transactions.

## Attack Chain

1. Attacker gains access to a network segment (L2/VLAN).
2. Attacker initiates DHCP starvation by generating a rapid burst of DHCP DISCOVER messages.
3. Attacker uses spoofed or randomized MAC addresses for each request to appear as distinct clients.
4. DHCP server receives the high volume of requests and allocates leases until the pool is exhausted.
5. Legitimate network clients are denied IP addresses, resulting in a loss of network connectivity.
6. Attacker deploys a rogue DHCP server to respond to subsequent requests, facilitating traffic interception.

## Impact

Observed impact includes total exhaustion of the DHCP lease pool, preventing legitimate devices from obtaining IP addresses. Successful exploitation often acts as a precursor to unauthorized network traffic interception via rogue DHCP server deployment.

## Recommendation

- Implement DHCP snooping and rate-limiting on access layer switches to prevent high-frequency DISCOVER bursts from single ports.
- Establish monitoring for DHCP server health, specifically tracking spikes in NAK responses and address pool utilization.
- Review network traffic sensor logs for high-cardinality MAC address activity associated with DHCP DISCOVER messages.
- Isolate suspected hosts generating disproportionately high volumes of DHCP requests upon confirmation.
