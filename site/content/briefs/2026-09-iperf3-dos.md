---
title: Denial of Service Vulnerability in iperf3
slug: 2026-09-iperf3-dos
description: An unauthenticated remote attacker can trigger a permanent 100% CPU utilization loop in iperf3 versions prior to 3.22 by sending a crafted control-channel message followed by a specific UDP datagram.
date: "2026-09-29T22:29:50Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:esnet:iperf:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - network-security
  - cve-2026-102253
vendors:
  - ESnet
products:
  - iperf3 (< 3.22)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: iperf3 versions prior to 3.22 contains a denial of service vulnerability that allows unauthenticated remote attackers to crash-loop the server's UDP receive worker
    confidence_band: high
cves:
  - id: CVE-2026-102253
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102253
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade iperf3 to 3.22 or later on all exposed infrastructure
      owner: IT Operations
      due: 48h
      evidence: Source indicates vulnerability exists in versions prior to 3.22
  mitigation_plan:
    - priority: immediate
      action: Restrict access to iperf3 control port (TCP 5201) via firewall
      owner: Network Security
      addresses: CVE-2026-102253
      evidence: Vulnerability requires an unauthenticated remote attacker to interact with the control channel
---

iperf3 versions prior to 3.22 contain a critical denial of service (DoS) vulnerability, tracked as CVE-2026-102253. The vulnerability allows an unauthenticated remote attacker to force the server's UDP receive worker into an unrecoverable infinite loop. The attack requires sending a single crafted control-channel parameter message, immediately followed by a specific 16-byte UDP datagram. 

Once triggered, the affected per-stream receive thread enters a state of approximately 100% CPU usage. Because the process stops responding to standard control-channel termination signals, the server becomes permanently unusable for new connections or existing streams until the process is manually terminated using a SIGKILL signal. This issue is particularly impactful for network performance monitoring infrastructure that relies on iperf3 for capacity testing. Defenders should upgrade to iperf3 version 3.22 or later to mitigate this risk.

## Impact

The vulnerability results in a complete service denial for the targeted iperf3 instance. Because the process enters a hang state that does not respond to standard signals, recovery requires manual administrative intervention (SIGKILL). This impacts all network sectors and environments utilizing iperf3 for throughput testing and network diagnostic verification.

## Recommendation

- Upgrade all instances of iperf3 to version 3.22 or later to remediate CVE-2026-102253.
- Implement network-level access control lists (ACLs) to restrict access to the iperf3 control channel (default port 5201) to authorized management subnets only.
- Monitor server CPU utilization for prolonged spikes reaching 100% on a single thread associated with the iperf3 process name as an indicator of an active DoS event.
