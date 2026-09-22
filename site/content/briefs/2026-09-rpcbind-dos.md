---
title: Denial of Service Vulnerability in rpcbind
slug: 2026-09-rpcbind-dos
description: CVE-2026-94640 allows a remote, unauthenticated attacker to trigger a denial of service in the rpcbind service through the submission of a flood of unique RPC requests that exhaust system memory.
date: "2026-09-22T16:38:12Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
cpes:
  - cpe:2.3:a:rpcbind_project:rpcbind:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - rpc
  - infrastructure
vendors:
  - rpcbind
products:
  - rpcbind
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: This vulnerability allows a remote, unauthenticated attacker to cause a Denial of Service (DoS) by sending a large number of unique requests.
    confidence_band: high
cves:
  - id: CVE-2026-94640
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94640
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Network Security
  immediate_actions:
    - action: Restrict access to port 111 via firewall to authorized segments only
      owner: Network Security
      due: 24h
      evidence: Mitigation of remote unauthenticated access
  mitigation_plan:
    - priority: immediate
      action: Upgrade rpcbind to patched version
      owner: IT Operations
      addresses: CVE-2026-94640
      evidence: NVD vulnerability disclosure
---

CVE-2026-94640 is a vulnerability in the rpcbind service, a utility that maps RPC services to universal addresses. The flaw resides in how the service manages internal statistics for incoming Remote Procedure Call (RPC) requests. Specifically, rpcbind maintains an in-memory list of RPC statistics to track unique request types. This list is unbounded, meaning there is no programmatic limit on the number of entries it can store. 

A remote, unauthenticated attacker can exploit this by sending a high volume of unique, crafted RPC requests to the rpcbind service. As the service processes these requests, it continuously appends new entries to the unbounded list. This leads to persistent, unrestricted memory growth and significant increases in CPU utilization as the service attempts to manage the expanding data structure. This resource exhaustion eventually results in the service becoming unresponsive or crashing, effectively denying service to legitimate users. Defenders should focus on monitoring for excessive RPC request volume targeting rpcbind instances, particularly from untrusted or external network segments.

## Impact

Successful exploitation of CVE-2026-94640 results in a Denial of Service (DoS) condition. This impacts any environment relying on rpcbind for RPC service mapping, potentially disrupting network services dependent on the RPC protocol. The vulnerability is highly relevant to infrastructure utilizing Unix-like systems where rpcbind is standard. If exploited, the service will consume available system memory and CPU, leading to application instability or system-wide resource contention.

## Recommendation

1. Monitor network traffic for anomalous spikes in RPC request volume directed toward TCP or UDP port 111 (the default port for rpcbind).
2. Implement network-level access control lists (ACLs) to restrict access to rpcbind from untrusted or public IP ranges, ensuring only authorized internal hosts can communicate with the service.
3. Patch rpcbind to the vendor-recommended version once updates are available for your specific Linux distribution.
4. Review system resource usage logs for rpcbind to identify abnormal memory growth trends that may indicate active exploitation.
