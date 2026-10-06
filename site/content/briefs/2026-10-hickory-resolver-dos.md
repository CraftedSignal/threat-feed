---
title: Resource Exhaustion in hickory-resolver via Unbounded TC-Retry Loop
slug: 2026-10-hickory-resolver-dos
description: The hickory-resolver DNS library is vulnerable to a denial-of-service condition (CVE-2025-27150) where a malicious authoritative nameserver can induce an infinite retry loop by returning truncated responses.
date: "2026-10-06T00:46:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:enalean:tuleap:*:*:*:*:enterprise:*:*:*
  - cpe:2.3:a:enalean:tuleap:*:*:*:*:community:*:*:*
tags:
  - denial-of-service
  - dns
  - rust
  - cve-2025-27150
vendors:
  - Hickory DNS
products:
  - hickory-resolver (>= 0.26.0-beta.1, < 0.26.2)
cves:
  - id: CVE-2025-27150
    cvss: 5.3
    epss: 0.00377
references:
  - https://github.com/advisories/GHSA-6w6g-hm98-mhgm
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade hickory-resolver to version 0.26.2
      owner: IT Operations
      due: 72h
      evidence: Source advisory specifies fixed version 0.26.2
  mitigation_plan:
    - priority: immediate
      action: Identify services using vulnerable crate versions
      owner: Application Security
      addresses: CVE-2025-27150
      evidence: Vulnerability exists in 0.26.0-beta.1 through 0.26.1
---

The `hickory-resolver` library, a popular DNS resolver implementation in Rust, contains a logic flaw within the `NameServerPool::try_send` function that allows for resource exhaustion. When the resolver receives a DNS response with the TC (truncated) flag set, it is programmed to retry the request using a different transport mechanism. However, the implementation fails to verify the transport state that previously provided the response and lacks a retry counter. Consequently, if a malicious authoritative nameserver sends a constant stream of responses with the `TC=1` bit set, the resolver enters an infinite loop, attempting to retry the request until the 5-second wall-clock deadline expires. This behavior leads to CPU and network resource exhaustion, effectively preventing the resolver from processing legitimate DNS queries for the duration of the timeout.

## Impact

Successful exploitation results in a Denial-of-Service (DoS) condition for applications relying on the `hickory-resolver` crate for DNS resolution. The vulnerability is highly relevant for network services, proxies, and infrastructure components that perform frequent outbound DNS queries, as attackers operating malicious authoritative nameservers can cause significant resolution latency or service outages.

## Recommendation

- Upgrade the `hickory-resolver` crate to version 0.26.2 or later to include the mandatory retry counter and transport validation logic.
- Review network infrastructure logs for abnormal spikes in UDP/TCP traffic originating from external DNS nameservers associated with high latency or timeout errors.
- Audit services utilizing versions 0.26.0-beta.1 through 0.26.1 for increased CPU usage or unresponsive DNS resolution threads.
