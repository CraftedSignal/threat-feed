---
brief_id: brief-2026-11-16-aiohttp-redos-ghsa-jm3w-gw2p-xjfj
event_id: brief-2026-11-16-aiohttp-redos-ghsa-jm3w-gw2p-xjfj
revision: 1
activity_at: "2026-11-16T17:11:48Z"
title: 'aio-libs aiohttp: Event loop stall in add_domain() wildcard matching (CVE-2026-128124)'
slug: 2026-11-aiohttp-redos-ghsa-jm3w-gw2p-xjfj
description: The aiohttp framework is vulnerable to a regular expression denial-of-service (ReDoS) attack when using domain masks with multiple wildcards, allowing a remote attacker to stall the event loop via long Host headers.
date: "2026-11-16T17:11:48Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:aio_libs:aiohttp:*:*:*:*:*:*:*:*
vendors:
  - aio-libs
products:
  - aiohttp
product_versions:
  - product: aiohttp
    range: <= 3.14.3
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    subtechnique_id: T1499.001
    subtechnique_name: OS Exhaustion Flood
    evidence: A remote attacker can repeatedly send such headers to a server configured with a multi-wildcard domain mask and stall the event loop.
    confidence_band: high
cves:
  - id: CVE-2026-128124
    epss: 0.0052
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-jm3w-gw2p-xjfj
  - https://cveawg.mitre.org/api/cve/CVE-2026-128124
  - https://github.com/aio-libs/aiohttp/commit/c6ac0e44c3c573ff9616f4a6a532992538b31e43
action_plan:
  priority: elevated
  hunt_leads:
    - lead: Identify requests containing unusually long 'Host' header strings directed at AIOHTTP services that utilize domain masking, potentially triggering event loop stalls.
      technique_id: T1499
      data_needed:
        - HTTP request logs
        - Application telemetry
        - Host header values
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: A remote attacker can repeatedly send such headers to a server configured with a multi-wildcard domain mask and stall the event loop.
  mitigation_plan:
    - priority: immediate
      action: Update aiohttp to version 3.14.4 or later
      evidence: This issue is fixed in version 3.14.4.
    - priority: short_term
      action: Audit codebase for usage of Application.add_domain() with multiple wildcards
      evidence: Use at most one * in a domain mask.
  gaps:
    - No reliable way to detect exploited ReDoS attempts solely via WAF or web logs without specific application-level performance metrics.
---

## Overview

The `Application.add_domain()` method in aiohttp version 3.14.3 and earlier converts asterisk wildcards in domain masks into greedy regular expression fragments (`[^:]*`). When a mask contains two or more wildcards, matching a long `Host` header that does not align with the mask results in polynomial time complexity. This can cause an event loop stall when processing crafted HTTP requests.

## Impact

A remote, unauthenticated attacker can cause a denial-of-service (DoS) condition by repeatedly sending requests with long `Host` headers to an application configured with a multi-wildcard domain mask. This blocks the asynchronous event loop, preventing the server from processing other concurrent requests.

## Recommendation

- Update aiohttp to version 3.14.4 or later immediately.
- If patching is not immediately feasible, restrict domain masks to use at most one wildcard (`*`) character.
- Review application configurations to identify any `add_domain()` calls utilizing multiple wildcards.
