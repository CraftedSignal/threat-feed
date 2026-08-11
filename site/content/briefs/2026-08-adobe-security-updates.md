---
title: Adobe Security Updates — August 2026
slug: 2026-08-adobe-security-updates
description: Roundup of Adobe security advisories published in August 2026.
date: "2026-08-03T23:42:20Z"
lastmod: "2026-08-11T18:36:33Z"
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
  - id: CVE-2026-71384
    cvss: 9.6
  - id: CVE-2026-48317
    cvss: 9.6
    epss: 0.00486
  - id: CVE-2026-48331
    cvss: 10
    epss: 0.00473
  - id: CVE-2026-21273
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21273
updates:
  - at: "2026-08-03T23:42:27Z"
    level: L2
    summary: added CVE-2026-48330, CVE-2026-48331
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-48330
      - https://nvd.nist.gov/vuln/detail/CVE-2026-48331
  - at: "2026-08-11T18:36:04Z"
    level: L2
    summary: added CVE-2026-21273, CVE-2026-48362, CVE-2026-71384
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-48362
      - https://nvd.nist.gov/vuln/detail/CVE-2026-71384
      - https://nvd.nist.gov/vuln/detail/CVE-2026-21273
---

This roundup covers 2 Adobe security vulnerabilities. CVSS base scores range from 9.6 to 10.0. None are reported as actively exploited at the time of release. The issues affect ColdFusion 2025.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-48362](#cve-2026-48362) | ColdFusion 2025 (<= 2025.0.11) | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-48362) (authoritative) |
| [CVE-2026-71384](#cve-2026-71384) | n/a | Critical | 9.6 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-71384) (authoritative) |


## CVE-2026-48362

CVE-2026-48362 is a critical OS command injection vulnerability in Adobe ColdFusion 2023 and 2025 that allows unauthenticated, remote attackers to achieve arbitrary code execution. The vulnerability does not require user interaction and impacts the scope of the application, posing a significant risk to affected environments.

Affected products:
- ColdFusion 2025 (<= 2025.0.11)
- ColdFusion 2023 (<= 2023.0.22)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-48362

## CVE-2026-71384

CVE-2026-71384 is an incorrect authorization vulnerability in Adobe ColdFusion 2023 and 2025. The flaw allows an unauthenticated, adjacent attacker to bypass security features, resulting in unauthorized read and write access, and potentially a denial-of-service condition. Although the vulnerable component is restricted to an administrative network zone by default, successful exploitation does not require user interaction.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-71384
