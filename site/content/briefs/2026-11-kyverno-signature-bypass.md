---
brief_id: brief-2026-11-05-kyverno-signature-bypass
event_id: brief-2026-11-05-kyverno-signature-bypass
revision: 1
activity_at: "2026-11-05T04:27:07Z"
title: 'Kyverno: Signature verification bypass via image tag cache poisoning (CVE-2026-122321)'
slug: 2026-11-kyverno-signature-bypass
description: Kyverno 1.18.0 before 1.19.2 contains a signature verification bypass in verifyImages because cached verification results are keyed by the image reference string rather than the verified digest.
date: "2026-11-05T04:27:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
products:
  - Kyverno 1.18.0 before 1.19.2 (< 1.19.2)
cves:
  - id: CVE-2026-122321
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122321
---

Kyverno 1.18.0 before 1.19.2 is vulnerable to a signature verification bypass in verifyImages. Cached verification results are keyed by the image reference string (such as a tag) instead of the verified digest, causing cache hits to skip signature and attestation checks. An attacker who can submit workloads and move a registry tag can warm the cache with a signed image, repoint the tag, and have Kyverno admit the workload and use mutateDigest to pin the unverified digest.
