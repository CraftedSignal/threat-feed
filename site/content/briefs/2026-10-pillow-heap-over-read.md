---
brief_id: brief-2026-10-29-pillow-heap-over-read
event_id: brief-2026-10-29-pillow-heap-over-read
revision: 1
activity_at: "2026-10-29T23:25:49Z"
title: 'Pillow: Heap over-read in WMF/EMF rendering (CVE-2026-96644)'
slug: 2026-10-pillow-heap-over-read
description: The Pillow library on Windows is vulnerable to a heap over-read when parsing crafted WMF/EMF image files that trigger dimension truncation in the native drawwmf handler.
date: "2026-10-29T23:25:49Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source-verified
cpes:
  - cpe:2.3:a:python:pillow:*:*:*:*:*:*:*:*
vendors:
  - Python Software Foundation
products:
  - Pillow (< 13.0.0)
affected_os:
  - Windows
cves:
  - id: CVE-2026-96644
    cvss: 8.1
    epss: 0.00384
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-9v9v-9qvf-h2hj
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96644
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Pillow to version 13.0.0 or later on all Windows systems
      owner: IT Operations
      due: 48h
      evidence: Pillow versions < 13.0.0 are documented as vulnerable in the GHSA advisory.
  hunt_leads:
    - lead: Identify applications loading crafted EMF/WMF files that trigger unexpected process crashes in the Pillow library
      data_needed:
        - Windows Application Event Logs (Event ID 1000 - Application Error)
        - Debugger logs (e.g., access violations or memory access errors in python.exe)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The native over-read can cause process crashes when processing a crafted metafile.
  mitigation_plan:
    - priority: immediate
      action: Patch Pillow to 13.0.0
      owner: IT Operations
      addresses: CVE-2026-96644
      evidence: GHSA-9v9v-9qvf-h2hj recommends upgrading to 13.0.0.
---

Pillow versions prior to 13.0.0 contain a heap over-read vulnerability in its Windows-specific `drawwmf` native handler. The vulnerability arises when processing WMF or EMF files where image dimensions (stored in 32-bit header fields) are truncated to 16-bit values during the memory allocation phase of rendering, while the subsequent memory copy operation uses the original 32-bit dimensions. An attacker can provide a crafted file that bypasses standard pixel-count decompression-bomb checks by setting a large width and small height, leading to a heap over-read which can result in process crashes or information disclosure. This issue only affects Windows builds where the native handler is compiled.

## Impact

Successful exploitation allows for reading out-of-bounds heap memory, which can lead to application termination (DoS) or the potential leakage of sensitive data stored in memory adjacent to the heap buffer.

## Recommendation

Update the Pillow library to version 13.0.0 or later across all Windows-based environments where it is utilized.
