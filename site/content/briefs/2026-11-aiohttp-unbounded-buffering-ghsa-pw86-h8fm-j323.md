---
brief_id: brief-2026-11-16-aiohttp-unbounded-buffering-ghsa-pw86-h8fm-j323
event_id: brief-2026-11-16-aiohttp-unbounded-buffering-ghsa-pw86-h8fm-j323
revision: 1
activity_at: "2026-11-16T17:12:13Z"
title: 'AIOHTTP: Unbounded memory consumption in upgrade requests (CVE-2026-128129)'
slug: 2026-11-aiohttp-unbounded-buffering-ghsa-pw86-h8fm-j323
description: A vulnerability in the AIOHTTP library allows remote attackers to cause denial-of-service via memory exhaustion by streaming unbounded data during a pending WebSocket upgrade request.
date: "2026-11-16T17:12:13Z"
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
cves:
  - id: CVE-2026-128129
    epss: 0.00635
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-pw86-h8fm-j323
  - https://cveawg.mitre.org/api/cve/CVE-2026-128129
  - https://github.com/aio-libs/aiohttp/commit/3d850ee9b92573c7e913821cbcb96005beb3f4df
action_plan:
  priority: elevated
  mitigation_plan:
    - priority: immediate
      action: Update aiohttp to version 3.14.4 or later.
      evidence: This issue is fixed in version 3.14.4.
  gaps:
    - Lack of specific application-level WAF signatures for this memory exhaustion vector.
---

## Overview

AIOHTTP, an asynchronous HTTP client/server framework, contains a vulnerability (CVE-2026-128129) where the server buffers all incoming data on a connection during an upgrade request (e.g., WebSocket handshake) without applying size limits or flow control. This behavior persists until the request handler completes its processing. A remote attacker can exploit this by streaming large volumes of data while the upgrade request is pending, leading to significant and unbounded memory consumption.

## Impact

Successful exploitation results in excessive server memory usage. Depending on the environment and resource availability, this can cause the application process to crash or trigger an out-of-memory (OOM) event, resulting in a denial-of-service for the affected service.

## Recommendation

- Update the `aiohttp` library to version 3.14.4 or later immediately. 
- If patching is not immediately feasible, assess the exposure of services utilizing WebSocket or upgrade-request handlers to untrusted network traffic. 
- Monitor application memory metrics for unexpected spikes associated with WebSocket connection handling.
