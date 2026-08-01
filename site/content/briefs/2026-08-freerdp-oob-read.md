---
title: Heap Out-of-Bounds Read in FreeRDP Glyph Caching
slug: 2026-08-freerdp-oob-read
description: FreeRDP versions 3.28.0 and earlier are vulnerable to a heap out-of-bounds read during the processing of malicious RDP server glyph fragments, allowing for potential client-side crashes or information disclosure.
date: "2026-08-01T13:51:54Z"
lastmod: "2026-08-01T15:50:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - memory-safety
  - remote-access
  - tls
  - man-in-the-middle
vendors:
  - FreeRDP
products:
  - FreeRDP (3.28.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: Under a trusted or misissued certificate chain, an attacker positioned to present such a certificate can bypass server identity verification.
    confidence_band: high
cves:
  - id: CVE-2026-67291
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67291
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66402
updates:
  - at: "2026-08-01T15:50:38Z"
    level: L2
    summary: 'merged source coverage: FreeRDP TLS Certificate Identity Validation Vulnerability'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-66402
---

FreeRDP versions 3.28.0 and earlier contain a heap out-of-bounds read vulnerability (CVE-2026-67291) within the glyph caching logic, specifically in the update_process_glyph_fragments() and glyph_cache_fragment_put() functions in libfreerdp/cache/glyph.c. The vulnerability exists because the client fails to properly validate the declared fragment size provided by the server against the actual size of the received buffer when processing GLYPH_FRAGMENT_ADD updates.

A malicious RDP server can exploit this by sending a crafted fragment header with an oversized declared size. When the client attempts to process this data, it reads beyond the allocated heap buffer, leading to an immediate crash or unauthorized memory access. This flaw poses a significant risk to users connecting to untrusted or compromised RDP servers, as the exploitation occurs during the standard RDP session establishment or update phase.

## Impact

Successful exploitation of CVE-2026-67291 results in a denial-of-service condition via a client-side crash. Because the vulnerability involves out-of-bounds memory reading, there is also a potential risk of sensitive information disclosure from the client heap. The flaw impacts any application or service utilizing FreeRDP libraries for RDP connectivity across Windows, Linux, and macOS environments.

## Recommendation

1. Upgrade all instances of FreeRDP to version 3.29.0 or later immediately to include the required boundary checks in libfreerdp/cache/glyph.c.
2. Implement egress network filtering for workstations or servers that rely on FreeRDP to connect to external RDP infrastructure, restricting connections only to trusted, verified RDP endpoints.
3. Audit internal RDP configurations to ensure that client machines are not configured to automatically connect to arbitrary or untrusted RDP servers.
