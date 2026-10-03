---
title: Praxis Proxy HTTP/2 HPACK Bomb Denial-of-Service Vulnerability
slug: 2026-10-praxis-h2-bomb
description: The Praxis proxy server is susceptible to a denial-of-service attack due to improper HTTP/2 header processing, allowing unauthenticated attackers to exhaust server memory through crafted HPACK compression sequences.
date: "2026-10-03T04:50:44Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - http2
  - proxy
  - memory-exhaustion
vendors:
  - Praxis
products:
  - Praxis (< 0.5.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The vulnerabilities target HPACK, the header compression scheme in HTTP/2, where a small request can trigger large memory allocations on the server.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-cjcg-cxmh-9wcr
  - https://blog.calif.io/p/codex-discovered-a-hidden-http2-bomb
  - https://access.redhat.com/security/vulnerabilities/RHSB-2026-007
  - https://github.com/praxis-proxy/pingora/commit/d193c8d49b8b7c1c1ede93183759caa4f6906bbd
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Praxis proxy instances to v0.5.2 or later
      owner: IT Operations
      due: 48h
      evidence: Source states bug was fixed in v0.5.2
  mitigation_plan:
    - priority: immediate
      action: Enforce H2 stream and header limits via upstream ingress/load balancer
      owner: IT Operations
      addresses: HTTP/2 HPACK bomb
      evidence: Source notes lack of configuration limits caused the vulnerability
---

Praxis, a proxy server built on the Pingora framework, is vulnerable to an HTTP/2 HPACK bomb attack. This vulnerability stems from a failure to correctly configure H2Options within the proxy's session initialization logic. Specifically, the affected version (v0.5.1 and earlier) does not enforce limits on the maximum header list size or the number of concurrent HTTP/2 streams. An attacker can exploit this by sending specially crafted, highly compressed HTTP/2 headers that cause the server to perform excessive memory allocations upon decompression. Observed testing indicates that a small volume of requests can force memory usage to spike from approximately 6MB to over 700MB, resulting in persistent memory exhaustion and potential service disruption. This vulnerability was fixed by implementing explicit H2Options in the handler configuration.

## Attack Chain

1. Attacker performs reconnaissance to identify a target infrastructure utilizing a vulnerable version of the Praxis proxy.
2. Attacker establishes an HTTP/2 connection with the target server.
3. Attacker crafts a series of malicious HTTP/2 requests containing high-compression ratio HPACK headers.
4. The target server's HPACK decoder receives the headers and attempts to decompress the payload.
5. Due to the lack of header list size or stream limits, the server allocates significant memory buffers to process the input.
6. Attacker repeats the request cycle to maximize memory pressure on the host environment.
7. The server encounters resource exhaustion, leading to degraded performance or service crashes.

## Impact

Successful exploitation results in a denial-of-service state for the Praxis proxy instance. Attackers can trigger rapid memory growth, causing potential process termination or impacting the availability of other co-located services on the same infrastructure. The vulnerability affects users of Praxis version 0.5.1 and earlier.

## Recommendation

1. Upgrade all instances of the Praxis proxy to version 0.5.2 or later to incorporate the corrected H2Options configuration.
2. Implement rate limiting and connection concurrency limits at the infrastructure layer (e.g., Load Balancer or WAF) to mitigate potential HTTP/2 flood and resource exhaustion attacks.
3. Monitor memory utilization metrics for proxy container instances; establish alerts for anomalous spikes in memory consumption associated with HTTP/2 traffic patterns.
