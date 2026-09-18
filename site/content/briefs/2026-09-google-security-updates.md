---
title: Google Security Updates - September 2026
slug: 2026-09-google-security-updates
description: Roundup of Google security advisories published in September 2026.
date: "2026-09-12T21:22:19Z"
lastmod: "2026-09-18T02:01:36Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - roundup
vendors:
  - Google
cves:
  - id: CVE-2026-90559
    cvss: 7.5
    epss: 0.0035
  - id: CVE-2026-93452
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93452
updates:
  - at: "2026-09-12T21:22:19Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-90559
  - at: "2026-09-18T02:01:36Z"
    level: L2
    summary: added CVE-2026-93452
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-93452
---

This roundup covers 1 Google security vulnerabilities. None are reported as actively exploited at the time of release.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-90559](#cve-2026-90559) | n/a |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-90559) (authoritative) |


## CVE-2026-90559

The snappy-java library, specifically the Snappy.uncompress method, contains an out-of-bounds write vulnerability due to a failure to validate destination buffer capacity against the decompressed data size. An attacker can craft compressed input that results in a buffer overflow during decompression, potentially leading to JVM crashes or arbitrary code execution.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-90559
