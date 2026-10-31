---
brief_id: brief-2026-10-31-libheif-heap-overflow
event_id: brief-2026-10-31-libheif-heap-overflow
revision: 1
activity_at: "2026-10-31T20:04:59Z"
title: 'libheif: Heap-based buffer overflow in unc_decoder_mixed_interleave (CVE-2026-120208)'
slug: 2026-10-libheif-heap-overflow
description: A heap-based buffer overflow vulnerability in libheif versions 1.18.0 through 1.23.2 allows out-of-bounds heap writes via crafted HEIF files with mismatched chroma bit depths, potentially facilitating arbitrary code execution.
date: "2026-10-31T20:04:59Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source verified
cpes:
  - cpe:2.3:a:libheif_project:libheif:*:*:*:*:*:*:*:*
vendors:
  - libheif
products:
  - libheif (1.18.0 to 1.23.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An attacker can leverage this flaw to trigger out-of-bounds heap writes, potentially leading to arbitrary code execution within the context of an application utilizing the library for image processing.
    confidence_band: high
cves:
  - id: CVE-2026-120208
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120208
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all applications, containers, and services utilizing libheif to verify if they fall within the 1.18.0-1.23.2 version range.
      owner: IT Operations
      due: 48h
      evidence: libheif 1.18.0 before 1.23.3 contains a heap-based buffer overflow
  hunt_leads:
    - lead: Identify applications invoking libheif to process uploaded images.
      technique_id: T1203
      data_needed:
        - Application dependency manifests
        - Software Bill of Materials (SBOM)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The vulnerability is triggered when processing a crafted HEIF image.
  mitigation_plan:
    - priority: immediate
      action: Upgrade libheif to version 1.23.3 or higher.
      owner: IT Operations
      addresses: CVE-2026-120208
      evidence: libheif 1.18.0 before 1.23.3 contains a heap-based buffer overflow vulnerability
---

libheif versions 1.18.0 through 1.23.2 are susceptible to a heap-based buffer overflow within the `unc_decoder_mixed_interleave::processTile()` function. The vulnerability is triggered when the library processes a maliciously crafted HEIF file that declares unequal bit depths for chroma components, such as a 16-bit Cb component combined with an 8-bit Cr component. This discrepancy causes an out-of-bounds write to the heap, which may result in application crashes or arbitrary code execution in the context of the processing pipeline.

## Impact

Successful exploitation may allow an unauthenticated attacker to execute arbitrary code within the memory space of an application leveraging the libheif library to decode images. Impact depends on the privileges of the application and the environment where image processing occurs.

## Recommendation

- Upgrade the libheif library to version 1.23.3 or later across all applications and services that use the library for image processing.
- Audit services (such as web servers, image hosting platforms, or content management systems) to identify instances where libheif is used to handle untrusted user-uploaded content.
- Implement strict input validation or sandboxing for any image-processing pipelines utilizing older, unpatched versions of libheif.
