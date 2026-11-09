---
brief_id: brief-2026-11-09-thorvg-heap-overflow
event_id: brief-2026-11-09-thorvg-heap-overflow
revision: 1
activity_at: "2026-11-09T21:59:15Z"
title: 'Thor Vector Graphics: Heap-based buffer overflow in jpgd JPEG decoder (CVE-2026-123367)'
slug: 2026-11-thorvg-heap-overflow
description: The Thor Vector Graphics (ThorVG) engine prior to 1.1.2 contains a heap buffer overflow vulnerability in its bundled jpgd JPEG decoder.
date: "2026-11-09T21:59:15Z"
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
  - cpe:2.3:a:thorvg:thor_vector_graphics:*:*:*:*:*:*:*:*
vendors:
  - ThorVG
products:
  - Thor Vector Graphics (< 1.1.2)
cves:
  - id: CVE-2026-123367
    cvss: 7.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123367
---

In Thor Vector Graphics (ThorVG) prior to version 1.1.2, the bundled jpgd JPEG decoder incorrectly handles duplicate component selectors in the SOS scan header. This error causes an increase in `m_blocks_per_mcu` without verifying buffers sized for frame components. A crafted grayscale JPEG can leverage this to trigger memory writes beyond heap buffers. This vulnerability is reachable through direct JPEG decoding and JPEG images embedded in Lottie content.

## Impact
The confirmed impact is memory corruption followed by a process crash.

## Remediation
This issue is fixed in version 1.1.2.
