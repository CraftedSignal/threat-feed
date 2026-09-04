---
title: Phoenix Transport Channel Exhaustion Denial of Service
slug: 2026-09-phoenix-dos
description: The Phoenix web framework lacks limits on channels per transport, allowing an unauthenticated attacker to cause a DoS by exhausting Erlang VM process limits via CVE-2026-56811.
date: "2026-09-04T00:05:32Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:phoenixframework:phoenix:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - web-framework
  - cve-2026-56811
vendors:
  - Phoenix
products:
  - Phoenix (>= 0.11.0, < 1.5.15)
  - Phoenix (>= 1.6.0-rc.0, < 1.6.17)
  - Phoenix (>= 1.7.0-rc.0, < 1.7.24)
  - Phoenix (>= 1.8.0-rc.0, < 1.8.9)
cves:
  - id: CVE-2026-56811
    cvss: 7.5
    epss: 0.00757
references:
  - https://github.com/advisories/GHSA-6983-jfq8-485w
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56811
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Phoenix to 1.5.15 or later
      owner: IT Operations
      due: 24h
      evidence: Source explicitly mandates upgrading to v1.5.15, v1.6.17, v1.7.24, or v1.8.9.
  mitigation_plan:
    - priority: immediate
      action: Apply connection-based rate limiting at the edge/load balancer
      owner: IT Operations
      addresses: CVE-2026-56811
      evidence: Source notes that limiting channels per transport forces attackers to open more connections, making standard rate limiting more effective.
---

The Phoenix web framework is vulnerable to a denial of service (DoS) condition due to an unbounded number of concurrent channel joins allowed over a single transport connection (LongPoll or WebSocket). By initiating a single connection, an unauthenticated remote attacker can programmatically trigger the creation of hundreds of thousands of Erlang processes. This behavior rapidly consumes system resources, eventually exceeding the Erlang VM's maximum process limit and resulting in a service crash. The issue, tracked as CVE-2026-56811, affects various versions across the 1.5, 1.6, 1.7, and 1.8 release branches. Defenders should note that because the exhaustion occurs within the application transport layer, standard infrastructure rate limiting may be ineffective unless applied at the connection level rather than the channel level.

## Impact

Successful exploitation results in a complete denial of service for any Phoenix-based application exposing LongPoll or WebSocket transports. As this does not require authentication, any internet-facing Phoenix instance is susceptible to resource exhaustion, potentially impacting critical production systems and causing significant downtime until the service is manually restarted or mitigated via patching.

## Recommendation

1. Patch Phoenix immediately to the corrected versions: v1.5.15, v1.6.17, v1.7.24, or v1.8.9.
2. Implement aggressive rate limiting on connection establishment at the load balancer or reverse proxy level to mitigate the impact of rapid connection cycles.
3. Monitor Erlang VM metrics, specifically process counts and memory usage, for anomalous spikes that do not correlate with legitimate user traffic volume.
