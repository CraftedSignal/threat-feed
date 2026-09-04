---
title: Heap-Based Buffer Overflow in Corosync Totem Process Group
slug: 2026-09-corosync-totempg-overflow
description: A heap-based buffer overflow in the Corosync Totem Process Group component allows a network-adjacent attacker to crash the cluster or potentially execute arbitrary code via crafted multicast messages.
date: "2026-09-04T09:25:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:corosync:corosync:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - heap-overflow
  - dos
vendors:
  - Corosync
products:
  - Corosync
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: A network-adjacent attacker able to send crafted multicast protocol messages to the cluster could cause a heap buffer overflow with attacker-controlled data, which can crash the Corosync daemon.
    confidence_band: high
cves:
  - id: CVE-2026-81665
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81665
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch all instances of Corosync immediately upon vendor release availability.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-81665 reported as heap-based buffer overflow.
  hunt_leads:
    - lead: Unexpected crash logs in /var/log/corosync.log or systemd journals.
      technique_id: T1498
      data_needed:
        - Log files from Corosync nodes
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability causes daemon crashes.
  mitigation_plan:
    - priority: immediate
      action: Restrict multicast traffic to only authorized management VLANs.
      owner: Network Security
      addresses: Network-adjacent exploitation vector
      evidence: Attack requires network adjacency to inject multicast messages.
  gaps:
    - Need to determine the patch level for current environment inventory.
---

CVE-2026-81665 describes a critical heap-based buffer overflow vulnerability in the Totem Process Group (totempg) message reassembly logic within the Corosync daemon. The flaw exists because the buffer allocated for reassembling fragmented multicast messages lacks sufficient runtime bounds checking in release builds. Corosync is a core cluster membership and messaging system commonly used in Linux high-availability environments. An attacker located on the local network segment, capable of injecting multicast traffic, can send malformed packets to the cluster. By triggering the buffer overflow, the attacker can cause a denial of service by crashing the Corosync daemon, which disrupts the cluster services. Given the nature of heap corruption, this vulnerability also presents a potential path for remote code execution if the attacker can exercise precise control over heap layout and state. This issue is particularly significant for environments that rely on cluster availability for mission-critical services.

## Attack Chain

1. Attacker establishes a presence on the local network segment (L2/L3 adjacency).
2. Attacker crafts malformed, fragmented multicast messages designed to exceed pre-allocated buffer sizes.
3. Attacker injects the crafted multicast packets onto the cluster's private interconnect network.
4. Corosync daemon receives and processes the malicious multicast fragment.
5. The totempg component performs reassembly without enforcing runtime bounds checking.
6. The heap buffer overflow occurs, overwriting adjacent memory structures with attacker-controlled data.
7. The Corosync daemon crashes due to memory corruption, leading to service disruption or node fencing.
8. If heap state is sufficiently controlled, the attacker gains the ability to overwrite function pointers or other control flow structures, enabling arbitrary code execution.

## Impact

The vulnerability poses a severe threat to cluster integrity and availability. Successful exploitation typically results in an immediate crash of the Corosync daemon, causing a denial of service (DoS) for all services managed by the cluster. In enterprise environments, this can lead to massive service outages, data inconsistency, and potential loss of data access. Depending on the environment, an attacker achieving code execution would gain the privileges of the user running the Corosync daemon, which is typically the root or a highly privileged service account.

## Recommendation

Prioritize the patching of all cluster nodes running the vulnerable Corosync daemon. Monitor cluster health for unexpected daemon restarts or nodes being fenced from the cluster, as these may indicate exploitation attempts. Utilize network segmentation to restrict access to the multicast traffic used by the cluster to only trusted infrastructure nodes.
