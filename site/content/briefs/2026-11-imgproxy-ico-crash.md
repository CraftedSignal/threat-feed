---
brief_id: brief-2026-11-01-imgproxy-ico-crash
event_id: brief-2026-11-01-imgproxy-ico-crash
revision: 1
activity_at: "2026-11-01T02:45:30Z"
title: 'imgproxy: Out-of-bounds heap write in ICO loader'
slug: 2026-11-imgproxy-ico-crash
description: An out-of-bounds heap write vulnerability in the imgproxy ICO loader allows unauthenticated attackers to trigger a deterministic worker crash (DoS) by supplying a crafted image file.
date: "2026-11-01T02:45:30Z"
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
tags:
  - denial-of-service
  - heap-overflow
  - memory-corruption
vendors:
  - imgproxy
products:
  - imgproxy (>= 3.3.0, < 4.0.17)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: 'The worker then aborts deterministically (glibc munmap_chunk(): invalid pointer → SIGABRT → Go panic, exit code 2).'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-494m-4556-wf5p
iocs:
  - type: hash_sha256
    value: 075f3b5e97242573d32a1b7612672a438b3b24c8fa718e3967305bd65e6151e1
ioc_counts:
  hash_sha256: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade imgproxy to 4.0.17
      owner: IT Operations
      due: 24h
      evidence: Vulnerable versions are < 4.0.17
  hunt_leads:
    - lead: Identify repeated imgproxy worker restarts or exit code 2 in orchestrator logs
      technique_id: T1499
      data_needed:
        - Kubernetes container status / logs
        - imgproxy standard error logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: One request, one dead worker. Worker aborts deterministically with exit code 2.
  mitigation_plan:
    - priority: immediate
      action: Upgrade imgproxy to 4.0.17
      owner: IT Operations
      addresses: imgproxy ICO loader OOB write
      evidence: GHSA-494m-4556-wf5p
---

imgproxy versions 3.3.0 through 4.0.15 contain an out-of-bounds heap write vulnerability in the ICO loader (`vips/icoload.c`). When processing an ICO file with a small declared image data size, the loader performs OOB reads and writes while reconstructing the BMP header. This causes memory corruption in the heap, specifically overwriting the size field of adjacent heap chunks. This corruption leads to a glibc `munmap_chunk()` error, causing the Go worker to abort (SIGABRT) and exit (exit code 2).

## Attack Chain

1. Attacker crafts a malicious ICO file containing a small `data_size` and specific header parameters.
2. Attacker sends an HTTP request to an exposed imgproxy endpoint to process the malicious ICO.
3. imgproxy passes the request to the underlying `vips` library.
4. The `vips_foreign_load_ico_header` function allocates a small heap buffer based on the malicious `data_size`.
5. The loader performs OOB reads from the malformed header and performs OOB writes during BMP reconstruction.
6. The size field of the following heap chunk is corrupted during the OOB write.
7. The application invokes `free()` on the corrupted chunk.
8. The glibc allocator detects the corruption and triggers `munmap_chunk(): invalid pointer`, leading to worker termination.

## Impact

Successful exploitation results in a persistent denial of service (DoS) for the specific worker process. Since a single request can trigger the abort, an attacker can crash workers at a rate proportional to the volume of requests sent to the vulnerable endpoint.

## Recommendation

1. Upgrade to imgproxy version 4.0.17 or later to incorporate the patch for the ICO loader heap memory corruption.
2. Implement request size limits and file validation filters to block unknown or suspicious ICO files before they reach the processing layer.
3. Deploy monitoring for worker process exit codes; alert on high frequencies of exit code 2 in imgproxy worker pods.
