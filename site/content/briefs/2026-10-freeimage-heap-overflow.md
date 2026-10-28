---
brief_id: brief-2026-10-28-freeimage-heap-overflow
event_id: brief-2026-10-28-freeimage-heap-overflow
revision: 1
activity_at: "2026-10-28T22:48:40Z"
title: 'FreeImage: Heap buffer overflow in PBM RLE decoder (CVE-2026-118752)'
slug: 2026-10-freeimage-heap-overflow
description: The danoli3 fork of the FreeImage library before 3.19.22 contains a heap buffer overflow in the PBM RLE decoder of PluginIFF.cpp due to missing bounds checks on ByteRun1 runs.
date: "2026-10-28T22:48:40Z"
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
  - FreeImage (danoli3 fork) < 3.19.22
cves:
  - id: CVE-2026-118752
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118752
---

CVE-2026-118752 affects the danoli3 fork of the FreeImage library prior to 3.19.22. A heap buffer overflow exists in the PBM RLE decoder of PluginIFF.cpp, which lacks bounds checks on ByteRun1 runs. Attackers can supply a crafted IFF/LBM PBM file with runs straddling scanline ends to write up to 127 controlled bytes past the heap-allocated bitmap.
