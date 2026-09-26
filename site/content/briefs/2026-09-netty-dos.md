---
title: Denial of Service in Netty via Unbounded HTTP Pipelined Request Queue
slug: 2026-09-netty-dos
description: An unbounded memory growth vulnerability in Netty's HttpServerCodec allows remote, unauthenticated attackers to trigger a denial of service via excessive HTTP/1.1 pipelined requests.
date: "2026-09-26T15:07:18Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:netty:netty:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - memory-exhaustion
  - vulnerability
  - network-protocol
products:
  - netty-codec-http (4.2.0.Final-4.2.17.Final, <= 4.1.137.Final)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A remote, unauthenticated attacker who pipelines HTTP/1.1 requests on a single connection while withholding reads on their own end... can grow this queue without bound, causing unbounded heap growth and denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-100656
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100656
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade affected Netty packages to 4.2.18.Final or 4.1.138.Final
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-100656 fix version
  mitigation_plan:
    - priority: immediate
      action: Patch CVE-2026-100656 on all internet-facing systems using Netty
      owner: IT Operations
      addresses: CVE-2026-100656
      evidence: Source advisory
---

Netty (io.netty:netty-codec-http) contains an unbounded per-connection queue growth flaw in the HttpServerCodec component. The codec tracks the HTTP method of each unanswered pipelined request. While the first 32 entries are optimized and bit-packed, any additional entries are appended to a methodOverflowQueue, which is an ArrayDeque with no size limit or rejection path.

A remote, unauthenticated attacker can exploit this flaw by sending a large volume of HTTP/1.1 pipelined requests over a single connection. By simultaneously slowing down their own connection reads, the attacker prevents the server from flushing responses, which in turn forces the codec to keep the corresponding entries in the queue indefinitely. This behavior allows the queue to grow without bound, leading to excessive heap consumption and eventual denial of service (DoS) for the affected service. The vulnerability affects Netty versions 4.2.0.Final through 4.2.17.Final and all releases up to and including 4.1.137.Final.

## Impact

Successful exploitation results in a denial of service for applications utilizing the affected Netty components. This impacts any service relying on Netty for high-performance HTTP networking, potentially disrupting connectivity for all users of the application. The severity is high due to the lack of authentication required to trigger the heap exhaustion and the ease with which an attacker can sustain the flood of requests.

## Recommendation

Prioritize patching all instances of the Netty framework identified in the environment.

- Upgrade netty-codec-http to version 4.2.18.Final or 4.1.138.Final to include the necessary queue size limits and rejection logic.
- Review network configurations to identify and limit excessively long-lived or slow-client HTTP/1.1 connections.
- Patch CVE-2026-100656 on all servers running affected Netty versions immediately.
