---
brief_id: brief-2026-11-16-aiohttp-form-dos-ghsa-xgw8-8ccx-rmqh
event_id: brief-2026-11-16-aiohttp-form-dos-ghsa-xgw8-8ccx-rmqh
revision: 1
activity_at: "2026-11-16T17:11:56Z"
title: 'aiohttp: Denial of service via URL-encoded form fields (CVE-2026-128126)'
slug: 2026-11-aiohttp-form-dos-ghsa-xgw8-8ccx-rmqh
description: The aiohttp framework is vulnerable to a denial-of-service attack due to inefficient parsing of URL-encoded form fields, allowing an attacker to block the event loop with a crafted POST request.
date: "2026-11-16T17:11:56Z"
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
    range: < 3.14.4
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.001
    technique_name: OS Exhaustion Flood
    evidence: An attacker could block the event loop with a form POST within the default client_max_size to any handler that calls Request.post().
    confidence_band: high
cves:
  - id: CVE-2026-128126
    epss: 0.0052
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-xgw8-8ccx-rmqh
  - https://cveawg.mitre.org/api/cve/CVE-2026-128126
  - https://github.com/aio-libs/aiohttp/commit/615fec3d4f088f30d2ee72cad760152e92aa1c53
action_plan:
  priority: elevated
  hunt_leads:
    - lead: Identify HTTP POST requests directed at aiohttp-based web services where the number of parameters or form fields in the request body is unusually high, indicating a potential attempt to trigger quadratic time complexity in MultiDict parsing and block the event loop.
      technique_id: T1499.001
      data_needed:
        - Web server access logs
        - Application request telemetry
        - WAF request body inspection logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: An attacker could block the event loop with a form POST within the default client_max_size to any handler that calls Request.post().
  mitigation_plan:
    - priority: immediate
      action: Upgrade aiohttp to 3.14.4 or later across all production environments
      evidence: This issue is fixed in version 3.14.4.
  gaps:
    - Lack of specific WAF signatures to detect high-volume repeated form fields without blocking legitimate traffic.
---

## Overview
AIOHTTP, an asynchronous HTTP client/server framework for Python, is vulnerable to a denial-of-service condition (CVE-2026-128126). The vulnerability exists because the Request.post() method fails to limit the number of fields processed in a URL-encoded form body. When a large number of repeated keys are provided, the internal processing of the MultiDict structure results in quadratic time complexity, which blocks the event loop and disrupts the application server.

## Impact
A remote attacker can cause a denial-of-service by sending a crafted HTTP POST request within the established client_max_size limits. Successful exploitation forces the server's event loop into a computationally expensive operation, rendering it unable to process other requests.

## Recommendation
Upgrade aiohttp to version 3.14.4 or later to implement necessary limits on form field processing. Identify all services utilizing aiohttp as a web server and ensure they are patched to the fixed version. Consult the official security advisory at the provided GitHub URL for detailed remediation steps.
