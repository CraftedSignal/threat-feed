---
title: Siemens Security Updates — July 2026
slug: 2026-07-siemens-security-updates
description: Roundup of Siemens security advisories published in July 2026.
date: "2026-07-07T16:48:32Z"
lastmod: "2026-07-16T16:10:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - roundup
vendors:
  - Siemens
  - Palo Alto Networks
products:
  - CPCI85 Central Processing/Communication < V26.20
  - SICORE Base system < V26.20.0
  - SIMATIC S7-PLCSIM Advanced (All versions)
  - CADRA (< V2511)
  - Desigo CC family V7/V8 (all versions)
  - Desigo CC family V9 (< V9.0 QU1)
  - IAM Client
  - Mendix Runtime (all versions)
  - Opcenter X (< V2604)
  - Palo Alto Networks PAN-OS on RUGGEDCOM APE1808 (all versions)
  - SIDIS Secured SmartPlug (< V7.26.0310)
  - SIMATIC S7-1500 CPU family (< V3.1.6)
  - Simcenter STAR-CCM+ (all versions)
  - CPCI85 Central Processing/Communication < 26.20
  - SICORE Base system < 26.20.0
  - SICAM A8000 Device firmware
  - CP-8031
  - CP-8050
  - SICAM EGS Device firmware
  - CP-8010
  - CP-8012
  - SICAM S8000
cves:
  - id: CVE-2026-48192
    cvss: 5.4
    epss: 0.00193
  - id: CVE-2026-54801
    cvss: 7.2
    epss: 0.0034
  - id: CVE-2026-54429
    cvss: 7.4
    epss: 0.00215
  - id: CVE-2026-54798
    cvss: 6.5
    epss: 0.0024
  - id: CVE-2026-54800
    cvss: 4.8
    epss: 0.00146
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54801
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54429
  - https://cyber.gc.ca/en/alerts-advisories/control-systems-siemens-security-advisory-av26-689
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-197-05
iocs:
  - type: url
    value: https://cert-portal.siemens.com/productcert/html/ssa-229470.html
ioc_counts:
  url: 1
updates:
  - at: "2026-07-09T15:18:49Z"
    level: L2
    summary: added CVE-2026-54801
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-54801
  - at: "2026-07-14T10:18:54Z"
    level: L2
    summary: added CVE-2026-54429
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-54429
  - at: "2026-07-14T13:40:25Z"
    level: L1
    summary: new product
    sources:
      - cccs
    source_urls:
      - https://cyber.gc.ca/en/alerts-advisories/control-systems-siemens-security-advisory-av26-689
  - at: "2026-07-16T16:10:50Z"
    level: L2
    summary: added CVE-2026-54798 +1
    sources:
      - cisa
    source_urls:
      - https://www.cisa.gov/news-events/ics-advisories/icsa-26-197-05
---

Aggregated Siemens security advisories for July 2026. CVEs from this cycle are folded
into the list below as they are published.

## Recommendation

Review affected products and apply Siemens's July 2026 security updates.
