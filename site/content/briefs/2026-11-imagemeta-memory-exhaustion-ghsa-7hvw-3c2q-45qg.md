---
brief_id: brief-2026-11-20-imagemeta-memory-exhaustion-ghsa-7hvw-3c2q-45qg
event_id: brief-2026-11-20-imagemeta-memory-exhaustion-ghsa-7hvw-3c2q-45qg
revision: 1
activity_at: "2026-11-20T02:03:40Z"
title: 'bep/imagemeta: Unbounded memory allocation in PNG parsing (CVE-2026-103025)'
slug: 2026-11-imagemeta-memory-exhaustion-ghsa-7hvw-3c2q-45qg
description: The bep/imagemeta Go library is vulnerable to memory exhaustion via crafted PNG files containing malformed zTXt chunks, allowing unauthenticated remote attackers to cause a denial-of-service.
date: "2026-11-20T02:03:40Z"
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
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:bep:imagemeta:*:*:*:*:*:*:*:*
vendors:
  - bep
products:
  - imagemeta
product_versions:
  - product: imagemeta
    range: < 0.17.3
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Applications that decode untrusted PNGs with IPTC metadata processing can therefore suffer denial of service through memory exhaustion.
cves:
  - id: CVE-2026-103025
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-7hvw-3c2q-45qg
  - https://cveawg.mitre.org/api/cve/CVE-2026-103025
action_plan:
  priority: elevated
  hunt_leads:
    - lead: Identify applications utilizing the bep/imagemeta library by monitoring for high memory growth or OOM (Out of Memory) events during or immediately following PNG image processing tasks, specifically those configured to parse IPTC metadata.
      technique_id: T1499
      data_needed:
        - Application memory usage metrics
        - Application logs indicating image processing activity
        - System OOM killer logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Applications that decode untrusted PNGs with IPTC metadata processing can therefore suffer denial of service through memory exhaustion.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to bep/imagemeta 0.17.3
      evidence: This issue is fixed in 0.17.3.
    - priority: short_term
      action: Implement input size boundaries for PNG files and disable IPTC parsing in imagemeta if unused
      evidence: Reject or bound PNG input size before calling Decode, or clear IPTC from Options.Sources if IPTC metadata is not required.
---

## Overview

The bep/imagemeta library, used for parsing image metadata (EXIF, IPTC, XMP), is vulnerable to memory exhaustion (CVE-2026-103025). The vulnerability exists in the handling of PNG `zTXt` chunks with the keyword "Raw profile type iptc". Attackers can exploit this by providing a crafted PNG file that triggers either an oversized memory allocation based on the declared chunk length or a memory-resident decompression bomb within the embedded zlib stream. This can lead to significant memory consumption, with reports of a 42-byte file causing a 256 MB allocation and a 127 KB file consuming 460 MB.

## Impact

Successful exploitation results in a denial-of-service (DoS) condition by exhausting available system memory. The severity of the memory impact is influenced by platform overcommit settings, configured `GOMEMLIMIT` values, and cgroup limits.

## Recommendation

- Update the `bep/imagemeta` library to version 0.17.3 or later.
- If patching is not immediately possible, implement input validation to reject excessively large or malformed PNG files before processing.
- If IPTC metadata processing is not required, disable it by clearing `IPTC` from the `Options.Sources` configuration.
