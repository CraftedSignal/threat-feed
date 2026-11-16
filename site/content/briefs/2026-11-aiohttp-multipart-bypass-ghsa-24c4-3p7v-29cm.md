---
brief_id: brief-2026-11-16-aiohttp-multipart-bypass-ghsa-24c4-3p7v-29cm
event_id: brief-2026-11-16-aiohttp-multipart-bypass-ghsa-24c4-3p7v-29cm
revision: 1
activity_at: "2026-11-16T17:12:05Z"
title: 'aio-libs aiohttp: BodyPartReader multipart memory exhaustion (CVE-2026-128127)'
slug: 2026-11-aiohttp-multipart-bypass-ghsa-24c4-3p7v-29cm
description: A vulnerability in the aiohttp BodyPartReader allows remote attackers to bypass client_max_size protections and trigger memory exhaustion or event loop blocking via crafted base64 multipart requests.
date: "2026-11-16T17:12:05Z"
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
    evidence: An attacker could bypass client_max_size to cause excessive memory use, or block the event loop, with a specially crafted multipart request to any handler that reads multipart data.
    confidence_band: high
cves:
  - id: CVE-2026-128127
    epss: 0.00546
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-24c4-3p7v-29cm
  - https://github.com/aio-libs/aiohttp/commit/a555ab698e08e9baea7386d5b4c0761cb8956fdd
  - https://cveawg.mitre.org/api/cve/CVE-2026-128127
action_plan:
  priority: immediate_escalation
  hunt_leads:
    - lead: 'Identify HTTP multipart requests that contain ''Content-Transfer-Encoding: base64'' headers targeting aiohttp services, specifically looking for anomalous request body sizes or sustained high CPU/memory utilization by the web service process following the arrival of a multipart request.'
      technique_id: T1499
      data_needed:
        - web_server_access_logs
        - process_memory_usage
        - cpu_utilization_metrics
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: An attacker could bypass client_max_size to cause excessive memory use, or block the event loop, with a specially crafted multipart request to any handler that reads multipart data.
  mitigation_plan:
    - priority: immediate
      action: Upgrade aiohttp to version 3.14.4 or later.
      evidence: This issue is fixed in version 3.14.4.
  gaps:
    - No direct telemetry available to identify exploitation attempts via standard logs without application-level instrumentation.
---

## Overview

The aiohttp library, an asynchronous HTTP client/server framework, contains a vulnerability (CVE-2026-128127) within its BodyPartReader component. When processing multipart parts with the header 'Content-Transfer-Encoding: base64', the method 'read_chunk()' fails to enforce a byte limit, continuing to read until a chunk length is a multiple of four. A malicious multipart request using a short 'Content-Length' or a large amount of whitespace can force the application to read the entire remaining body into memory before the size check occurs, or cause the process to spin on the event loop.

## Impact

Successful exploitation allows a remote, unauthenticated attacker to bypass the 'client_max_size' limit configured for the application. This can lead to excessive memory consumption, which may result in a denial-of-service, or the blocking of the event loop, causing the application to become unresponsive to legitimate traffic.

## Recommendation

- Update all instances of aiohttp to version 3.14.4 or later immediately. The maintainers have introduced the necessary byte limit enforcement to mitigate this issue in the patched release.
- Audit web handlers within your application that accept multipart/form-data to confirm they rely on global 'client_max_size' settings and evaluate if individual processing logic exposes the vulnerability prior to patching.
