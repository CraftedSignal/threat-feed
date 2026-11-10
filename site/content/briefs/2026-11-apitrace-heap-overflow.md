---
brief_id: brief-2026-11-10-apitrace-heap-overflow
event_id: brief-2026-11-10-apitrace-heap-overflow
revision: 1
activity_at: "2026-11-10T18:28:18Z"
title: 'apitrace: Heap-based buffer overflow in SnappyFile::flushReadCache (CVE-2026-126050)'
slug: 2026-11-apitrace-heap-overflow
description: apitrace versions 2.0 through 14.0 contain a heap-based buffer overflow in the SnappyFile::flushReadCache() function, allowing attackers to write past the m_compressedCache buffer via a crafted .trace file.
date: "2026-11-10T18:28:18Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
products:
  - apitrace (2.0 through 14.0)
cves:
  - id: CVE-2026-126050
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-126050
---

A heap-based buffer overflow exists in apitrace versions 2.0 through 14.0 within the `SnappyFile::flushReadCache()` function. Attackers can supply a crafted `.trace` file with a 4-byte chunk length that exceeds the fixed size of the `m_compressedCache` buffer. When users dump, inspect, or replay these files, heap memory is corrupted.
