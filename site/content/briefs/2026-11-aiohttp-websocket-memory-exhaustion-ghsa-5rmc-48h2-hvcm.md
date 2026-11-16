---
brief_id: brief-2026-11-16-aiohttp-websocket-memory-exhaustion-ghsa-5rmc-48h2-hvcm
event_id: brief-2026-11-16-aiohttp-websocket-memory-exhaustion-ghsa-5rmc-48h2-hvcm
revision: 1
activity_at: "2026-11-16T17:12:38Z"
title: 'AIOHTTP: WebSocket memory exhaustion (CVE-2026-128132)'
slug: 2026-11-aiohttp-websocket-memory-exhaustion-ghsa-5rmc-48h2-hvcm
description: AIOHTTP prior to 3.14.4 is vulnerable to memory exhaustion via WebSocket frames that bypass queue limit enforcement, allowing remote peers to consume excessive memory through high-frequency small or compressed messages.
date: "2026-11-16T17:12:38Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:aio_libs:aiohttp:*:*:*:*:*:*:*:*
vendors:
  - aio-libs
products:
  - aiohttp
product_versions:
  - product: aiohttp
    range: < 3.14.4
cves:
  - id: CVE-2026-128132
    epss: 0.00442
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-5rmc-48h2-hvcm
  - https://cveawg.mitre.org/api/cve/CVE-2026-128132
  - https://github.com/aio-libs/aiohttp/commit/0ae507423f681161efa77d20052b4054397c7fb6
action_plan:
  priority: elevated
  mitigation_plan:
    - priority: immediate
      action: Upgrade aiohttp to version 3.14.4 or later
      evidence: This issue is fixed in version 3.14.4.
  gaps:
    - No direct log-based detection is available for this internal memory management flaw; focus on dependency inventory management.
---

## Overview

An improper limitation of resources in AIOHTTP's WebSocket implementation allows a remote peer to bypass receive queue size limits. The vulnerability stems from two issues: the WebSocket reader continues to parse frames even after the transport is paused, and empty messages are not correctly counted toward the queue capacity. Additionally, the use of permessage-deflate compression allows a single read of compressed frames to expand into significant memory usage within the receive queue. Attackers can leverage these flaws by sending a high volume of small or highly compressed messages, faster than the application can process them, leading to excessive memory consumption on either the server or the client.

## Impact

Successful exploitation leads to a denial of service (DoS) state due to excessive memory usage, which can affect both WebSocket servers and clients using the affected versions of AIOHTTP.

## Recommendation

Upgrade the aiohttp package to version 3.14.4 or later immediately. Users should review their application's dependency manifest to identify environments running versions <= 3.14.3.
