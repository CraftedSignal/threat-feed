---
brief_id: brief-2026-11-03-freerdp-tls-bypass
event_id: brief-2026-11-03-freerdp-tls-bypass
revision: 2
activity_at: "2026-11-04T17:09:57Z"
revision_history:
  - revision: 2
    at: "2026-11-04T17:09:57Z"
    checksum: sha256:582ab0a9ce1089784c37e6f6649a622985b625cd4bd8f29d2482b82be5719a5c
    summary: added CVE-2026-121953
    changed_fields:
      - affected_vendors
      - claim_state
      - cpes
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/freerdp-3-32-2-memory-corruption-cert-bypass-cves
title: 'FreeRDP: TLS certificate validation bypass (CVE-2026-121392)'
slug: 2026-11-freerdp-tls-bypass
description: FreeRDP contains a certificate validation vulnerability in tls_verify_certificate() that allows man-in-the-middle attackers to intercept RDP sessions. A public PoC exploit has been published.
date: "2026-11-03T17:15:30Z"
lastmod: "2026-11-04T17:09:24Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://sploitus.com/exploit?id=CVE-2026-121392&utm_source=rss&utm_medium=rss
  observed_at: "2026-11-03T00:00:00Z"
  confidence: high
source_assessment:
  reliability: C
  credibility: "2"
  rating: C2
  likelihood: likely
cpes:
  - cpe:2.3:a:freerdp:freerdp:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-access
  - freerdp
vendors:
  - FreeRDP
cves:
  - id: CVE-2026-121392
    cvss: 7.4
    kev_status: "false"
  - id: CVE-2026-121953
    cvss: 9.8
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=CVE-2026-121392&utm_source=rss&utm_medium=rss
  - https://www.vulncheck.com/advisories/freerdp-before-3.32.2-certificate-identity-validation-bypass-via-tls-verify-certificate
  - https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-jq25-3374-4262
  - https://pwn.watch/i/freerdp-3-32-2-memory-corruption-cert-bypass-cves
  - https://github.com/FreeRDP/FreeRDP/releases/tag/3.32.2
  - https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-6wqx-rv3q-vcxp
  - https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-xc85-4mqc-xgcx
  - https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-m59q-wm7v-mp57
  - https://www.cve.org/CVERecord?id=CVE-2026-121953
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121392
updates:
  - at: "2026-11-04T17:09:24Z"
    level: L2
    summary: added CVE-2026-121953
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/freerdp-3-32-2-memory-corruption-cert-bypass-cves
---

FreeRDP contains an improper certificate validation vulnerability in tls_verify_certificate() that accepts Common Name fallback despite non-matching SAN entries and matches IP literals against DNS strings. Man-in-the-middle attackers holding a certificate from a client-trusted CA can bypass server identity checks to intercept RDP sessions, including keystrokes, clipboard, and screen content. A proof-of-concept exploit is available on Sploitus.
