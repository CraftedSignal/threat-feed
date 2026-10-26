---
brief_id: brief-2026-10-apple-security-updates
event_id: brief-2026-10-apple-security-updates
revision: 1
activity_at: "2026-10-26T23:47:50Z"
title: Apple Security Updates - October 2026
slug: 2026-10-apple-security-updates
description: Roundup of Apple security advisories published in October 2026.
date: "2026-10-26T23:47:50Z"
lastmod: "2026-10-26T23:47:54Z"
type: threat
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
tags:
  - roundup
vendors:
  - Apple
cves:
  - id: CVE-2026-112427
    cvss: 8.1
    kev_status: "false"
  - id: CVE-2026-112438
    product: macOS
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-112484
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112484
updates:
  - at: "2026-10-26T23:47:50Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-112427
  - at: "2026-10-26T23:47:54Z"
    level: L2
    summary: added CVE-2026-112438, CVE-2026-112484
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-112438
      - https://nvd.nist.gov/vuln/detail/CVE-2026-112484
---

This roundup covers 2 Apple security vulnerabilities. CVSS base scores range from 8.1 to 8.8. None are reported as actively exploited at the time of release. The issues affect macOS.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-112427](#cve-2026-112427) | n/a | High | 8.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-112427) (authoritative) |
| [CVE-2026-112438](#cve-2026-112438) | macOS | High | 8.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-112438) (authoritative) |


## CVE-2026-112427

CVE-2026-112427 is an authentication vulnerability in macOS Golden Gate due to improper state management. A remote attacker could exploit this flaw to achieve arbitrary code execution on the target system.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-112427

## CVE-2026-112438

A logic vulnerability in macOS versions Golden Gate 27.2, Sequoia 15.8.2, and Tahoe 26.7.2 allows an unprivileged attacker to perform privilege escalation and execute arbitrary code as root by exploiting improved state management flaws.

Affected products:
- macOS

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-112438
