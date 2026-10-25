---
brief_id: brief-2026-10-25-openjpeg-heap-overflow
event_id: brief-2026-10-25-openjpeg-heap-overflow
revision: 1
activity_at: "2026-10-25T00:10:18Z"
title: 'OpenJPEG: Heap buffer overflow in opj_dwt_encode_and_deinterleave_v (CVE-2026-107080)'
slug: 2026-10-openjpeg-heap-overflow
description: OpenJPEG versions 2.4.0 through 2.5.4 and current git master are vulnerable to a heap buffer overflow in the opj_dwt_encode_and_deinterleave_v function, which can be triggered during reversible 5/3 forward DWT encoding to cause a denial of service.
date: "2026-10-25T00:10:18Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source verified, no detection possible without crash telemetry/EDR specific to libopenjp2 memory corruption
cpes:
  - cpe:2.3:a:openjpeg:openjpeg:2.4.0:*:*:*:*:*:*:*
  - cpe:2.3:a:openjpeg:openjpeg:2.5.4:*:*:*:*:*:*:*
vendors:
  - OpenJPEG
products:
  - OpenJPEG (2.4.0 - 2.5.4, git master through 8314119b)
cves:
  - id: CVE-2026-107080
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/375
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
    - Detection Engineering
  enrichment_needed:
    - item: CVE-2026-107080
      owner: CTI
      reason: Monitor for patch availability and vendor disclosure
      evidence: The fix proposed upstream has not been merged
  hunt_leads:
    - lead: Identify applications using OpenJPEG library versions 2.4.0-2.5.4
      data_needed:
        - Software Bill of Materials (SBOM)
        - Dependency scanning reports
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: OpenJPEG 2.4.0 through 2.5.4... contains an out-of-bounds read and write
  mitigation_plan:
    - priority: medium
      action: Apply future security updates once the upstream fix for CVE-2026-107080 is merged and released
      owner: IT Operations
      addresses: CVE-2026-107080
      evidence: The fix proposed upstream has not been merged
---

OpenJPEG versions 2.4.0 through 2.5.4, and the git master branch up to commit 8314119b, contain an out-of-bounds read and write vulnerability in the `opj_dwt_encode_and_deinterleave_v()` function located in `src/lib/openjp2/dwt.c`. This heap buffer overflow occurs during the reversible 5/3 forward Discrete Wavelet Transform (DWT) encoding process. The vulnerability is currently unpatched in the upstream repository.

## Impact

An attacker who can influence the input provided to the OpenJPEG encoder can trigger this heap buffer overflow, resulting in a denial of service (DoS) for the application utilizing the library.

## Recommendation

* Inventory applications and services in your environment that utilize the OpenJPEG library (versions 2.4.0 to 2.5.4).
* Monitor upstream OpenJPEG development for the release of an official patch for CVE-2026-107080.
* If the library is embedded, consider restricting input processing for untrusted JPEG 2000 images until a security update is applied.
