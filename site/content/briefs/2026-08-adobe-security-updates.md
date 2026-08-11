---
title: Adobe Security Updates — August 2026
slug: 2026-08-adobe-security-updates
description: Roundup of Adobe security advisories published in August 2026.
date: "2026-08-03T23:42:20Z"
lastmod: "2026-08-11T18:36:12Z"
type: threat
types:
  - threat
severities:
  - high
cpes:
  - cpe:2.3:a:adobe:campaign:*:*:*:*:classic:*:*:*
  - cpe:2.3:a:adobe:campaign:7.4.3:9394:*:*:classic:*:*:*
  - cpe:2.3:a:adobe:campaign:7.4.3:9396:*:*:classic:*:*:*
  - cpe:2.3:a:adobe:campaign:7.4.3:9397:*:*:classic:*:*:*
  - cpe:2.3:a:adobe:campaign:7.4.3:9398:*:*:classic:*:*:*
tags:
  - roundup
vendors:
  - Adobe
cves:
  - id: CVE-2026-48362
    product: ColdFusion 2025 (<= 2025.0.11)
    cvss: 10
  - id: CVE-2026-48317
    cvss: 9.6
    epss: 0.00486
  - id: CVE-2026-48331
    cvss: 10
    epss: 0.00473
  - id: CVE-2026-71384
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71384
updates:
  - at: "2026-08-03T23:42:25Z"
    level: L2
    summary: added CVE-2026-48326, CVE-2026-48330, CVE-2026-48331
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-48326
      - https://nvd.nist.gov/vuln/detail/CVE-2026-48330
      - https://nvd.nist.gov/vuln/detail/CVE-2026-48331
  - at: "2026-08-11T18:36:04Z"
    level: L2
    summary: added CVE-2026-48362, CVE-2026-71384
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-48362
      - https://nvd.nist.gov/vuln/detail/CVE-2026-71384
---

This roundup covers 1 Adobe security vulnerabilities. All have a CVSS base score of 10.0. None are reported as actively exploited at the time of release. The issues affect ColdFusion 2025.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-48362](#cve-2026-48362) | ColdFusion 2025 (<= 2025.0.11) | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48362) (authoritative) |


## CVE-2026-48362

CVE-2026-48362 is a critical OS command injection vulnerability in Adobe ColdFusion 2023 and 2025 that allows unauthenticated, remote attackers to achieve arbitrary code execution. The vulnerability does not require user interaction and impacts the scope of the application, posing a significant risk to affected environments.

Affected products:
- ColdFusion 2025 (<= 2025.0.11)
- ColdFusion 2023 (<= 2023.0.22)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48362
