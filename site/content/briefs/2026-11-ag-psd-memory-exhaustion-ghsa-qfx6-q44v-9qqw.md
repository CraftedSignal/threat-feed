---
brief_id: brief-2026-11-14-ag-psd-memory-exhaustion-ghsa-qfx6-q44v-9qqw
event_id: brief-2026-11-14-ag-psd-memory-exhaustion-ghsa-qfx6-q44v-9qqw
revision: 1
activity_at: "2026-11-14T08:22:54Z"
title: 'ag-psd: Uncontrolled memory allocation denial-of-service (CVE-2026-62297)'
slug: 2026-11-ag-psd-memory-exhaustion-ghsa-qfx6-q44v-9qqw
description: The ag-psd library is vulnerable to a remote denial-of-service attack due to improper validation of PSD header dimensions, which allows an attacker to trigger excessive memory allocation and crash the host process.
date: "2026-11-14T08:22:54Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Advisory verified against GHSA source; patch version confirmed
cpes:
  - cpe:2.3:a:ag-psd_project:ag-psd:*:*:*:*:*:node.js:*:*
products:
  - ag-psd
product_versions:
  - product: ag-psd
    range: < 31.0.0
cves:
  - id: CVE-2026-62297
    cvss: 7.5
    epss: 0.00339
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-qfx6-q44v-9qqw
iocs:
  - type: hash_sha256
    value: a1146a6fabdfef289472f99a56851249e7a46e8d19d4d8bf85fe833e2f0158b6
ioc_counts:
  hash_sha256: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade ag-psd dependency to version 31.0.0 or later
      owner: IT Operations
      due: 48h
      evidence: GHSA-qfx6-q44v-9qqw advisory
  hunt_leads:
    - lead: Identify applications using ag-psd and monitor for abnormally high process memory spikes or OOM events associated with file parsing services
      data_needed:
        - Application performance monitoring logs
        - Container orchestration (K8s/Docker) OOM exit codes
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The advisory notes the library commits multi-gigabyte allocations before failing, which triggers OOM kills on most hosts.
  mitigation_plan:
    - priority: immediate
      action: Upgrade ag-psd to 31.0.0 or later
      owner: IT Operations
      addresses: CVE-2026-62297
      evidence: GHSA-qfx6-q44v-9qqw
---

The ag-psd library (npm package) is vulnerable to an uncontrolled-allocation denial-of-service (CVE-2026-62297). The vulnerable function `readPsd()` commits image and layer buffers based on declared dimensions within the PSD header before validating these values against the actual available data. An attacker can supply a specially crafted, small PSD file that declares extremely large dimensions, causing the application to attempt to allocate massive amounts of memory, leading to OOM (Out of Memory) termination of the process.

## Impact

Successful exploitation results in immediate service denial through process termination. On version 30.2.0, a 52-byte file was observed to force a ~3.17 GB allocation before failing. This impacts any service using the `ag-psd` library to parse untrusted PSD input.

## Recommendation

- Update the `ag-psd` package to version 31.0.0 or later immediately.
- Implement strict file size limits and sanity checks on all user-provided image uploads before passing data to parsing libraries.
- Audit existing services to identify where `readPsd()` is exposed to untrusted user input.
