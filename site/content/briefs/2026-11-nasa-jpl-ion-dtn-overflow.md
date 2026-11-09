---
brief_id: brief-2026-11-09-nasa-jpl-ion-dtn-overflow
event_id: brief-2026-11-09-nasa-jpl-ion-dtn-overflow
revision: 1
activity_at: "2026-11-09T19:51:44Z"
title: 'NASA JPL ION-DTN: Heap-based buffer overflow in Network Management daemon (CVE-2026-123999)'
slug: 2026-11-nasa-jpl-ion-dtn-overflow
description: NASA JPL ION-DTN versions 3.6.2 through 4.2.0 contain a heap-based buffer overflow in the Network Management daemon (nm_mgr) that can cause a denial of service.
date: "2026-11-09T19:51:44Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:nasa:ion_dtn:*:*:*:*:*:*:*:*
vendors:
  - NASA
products:
  - ION-DTN (3.6.2 through 4.2.0)
cves:
  - id: CVE-2026-123999
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123999
---

NASA JPL ION-DTN versions 3.6.2 through 4.2.0 contain a heap-based buffer overflow in the Network Management daemon (nm_mgr) string-formatting logic. A malicious or misconfigured agent can trigger an out-of-bounds write via deeply nested AMP payloads that exceed fixed-size buffer allocations through unbounded strcat operations. Attackers can transmit oversized AMP reports, tables, or macros over the UDP CLA/AMP path, or trigger the flaw locally via interactive UI rendering, to crash nm_mgr and cause a denial of service, halting telemetry collection and operator visibility.
