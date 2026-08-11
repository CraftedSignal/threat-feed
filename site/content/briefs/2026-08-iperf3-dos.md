---
title: Resource Exhaustion Vulnerability in iperf3
slug: 2026-08-iperf3-dos
description: A remote denial-of-service vulnerability in iperf3, tracked as CVE-2026-71217, allows unauthenticated attackers to trigger resource exhaustion through crafted control-channel JSON packets.
date: "2026-08-11T10:31:43Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - ESnet
products:
  - iperf3
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: This improper input validation can lead to excessive stream and thread creation, as well as large buffer allocations, causing resource exhaustion.
    confidence_band: high
cves:
  - id: CVE-2026-71217
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71217
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Review inventory of iperf3 server instances exposed to untrusted networks.
      owner: SOC
      due: 48h
      evidence: CVE-2026-71217 represents a remote, unauthenticated DoS vector.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to TCP port 5201 via network firewall rules.
      owner: IT Operations
      addresses: CVE-2026-71217
      evidence: Vulnerability allows remote unauthenticated exploitation.
---

A vulnerability identified as CVE-2026-71217 exists within iperf3, a widely used tool for active measurements of the maximum achievable bandwidth on IP networks. The issue arises from improper validation of numeric parameters within the control-channel JSON communication protocol. Specifically, a remote attacker can submit crafted control-channel messages containing oversized values for fields such as "parallel" and "len". Because the iperf3 server fails to sanitize these inputs, the application attempts to allocate large buffers and spawn excessive threads or streams based on the malicious parameters. This results in significant resource exhaustion, effectively rendering the iperf3 server unavailable to legitimate users. As iperf3 is frequently deployed in network infrastructure and monitoring environments, this Denial of Service (DoS) vulnerability can disrupt critical diagnostic capabilities. Defenders should prioritize patching or restricting access to iperf3 server instances.

## Impact

Successful exploitation leads to a complete Denial of Service of the iperf3 server process. Given that iperf3 is commonly used by network administrators for troubleshooting and capacity planning, an outage of this tool can delay incident response or diagnostic workflows. The vulnerability affects all platforms where iperf3 is deployed, including Linux, Windows, and macOS environments.

## Recommendation

* Monitor network traffic directed at iperf3 listening ports (default TCP 5201) for anomalous, large, or frequent JSON-formatted control-channel requests.
* Patch or update iperf3 instances to the version containing the fix for CVE-2026-71217 as soon as it becomes available from ESnet or distribution repositories.
* Implement network-level access control lists (ACLs) to restrict access to iperf3 server ports to authorized management workstations only.
