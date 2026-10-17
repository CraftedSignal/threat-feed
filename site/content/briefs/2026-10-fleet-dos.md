---
title: Denial of Service Vulnerability in Fleet
slug: 2026-10-fleet-dos
description: Fleet versions prior to 4.83.0 are susceptible to a memory exhaustion denial of service attack via crafted gzip-compressed request bodies.
date: "2026-10-17T20:54:10Z"
lastmod: "2026-10-17T22:08:22Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:fleetdm:fleet:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - fleet
  - mdm
vendors:
  - Fleet
products:
  - Fleet (< 4.83.0)
  - Fleet (< 4.89.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: 'Attackers can send small, highly compressed requests with Content-Encoding: gzip to unauthenticated endpoints that expand during decoding, crashing the entire Fleet instance.'
    confidence_band: high
cves:
  - id: CVE-2026-111924
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111924
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111923
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Fleet to version 4.83.0 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-111924 vulnerability disclosure.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Fleet to 4.83.0.
      owner: IT Operations
      addresses: CVE-2026-111924
      evidence: NVD vulnerability details.
updates:
  - at: "2026-10-17T22:08:22Z"
    level: L1
    summary: added coverage for Fleet (< 4.89.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-111923
---

Fleet versions prior to 4.83.0 contain a denial of service vulnerability identified as CVE-2026-111924. This vulnerability resides in the application's handling of gzip-compressed request bodies, allowing unauthenticated attackers to exhaust server memory resources. By submitting small, highly compressed payloads with the 'Content-Encoding: gzip' header to unauthenticated endpoints, an attacker can trigger excessive memory consumption during the server-side decompression process. This exploitation path causes the Fleet instance to crash, resulting in a complete service disruption. As this vector does not require authentication, it represents a significant availability risk for internet-facing or otherwise exposed Fleet installations. Defenders should prioritize patching to version 4.83.0 or later to mitigate this risk.

## Impact

Successful exploitation of this vulnerability leads to a denial of service (DoS) state, where the Fleet instance becomes unresponsive or crashes due to memory exhaustion. This impact is relevant to any organization deploying Fleet for infrastructure management, as it allows any unauthenticated network actor to disrupt fleet-wide operations.

## Recommendation

* Upgrade Fleet installations to version 4.83.0 or later immediately to address the underlying memory handling flaw.
* Monitor webserver and application logs for anomalous 'Content-Encoding: gzip' headers on high-frequency or unauthorized request paths.
* Apply request size limits and compression ratio constraints at the edge (load balancer or WAF) to mitigate memory exhaustion risks until the patch is deployed.
