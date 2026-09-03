---
title: Adobe Security Updates - September 2026
slug: 2026-09-adobe-security-updates
description: Roundup of Adobe security advisories published in September 2026.
date: "2026-09-03T19:22:39Z"
lastmod: "2026-09-03T19:22:39Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - roundup
vendors:
  - Adobe
cves:
  - id: CVE-2026-83959
    product: Substance 3D Sampler
updates:
  - at: "2026-09-03T19:22:39Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-83959
---

This roundup covers 1 Adobe security vulnerabilities. None are reported as actively exploited at the time of release. The issues affect Substance 3D Sampler.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-83959](#cve-2026-83959) | Substance 3D Sampler |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83959) (authoritative) |


## CVE-2026-83959

Adobe Substance 3D Sampler contains a heap-based buffer overflow vulnerability triggered by opening a malicious file. Successful exploitation allows an attacker to achieve arbitrary code execution in the context of the current user, requiring user interaction to open the crafted file.

Affected products:
- Substance 3D Sampler

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83959
