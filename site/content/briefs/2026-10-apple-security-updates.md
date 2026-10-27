---
brief_id: brief-2026-10-apple-security-updates
event_id: brief-2026-10-apple-security-updates
revision: 2
activity_at: "2026-10-27T01:53:19Z"
revision_history:
  - revision: 2
    at: "2026-10-27T01:53:19Z"
    checksum: sha256:fad71cf75da994468372fcb7b7b4556350c99b4a5751fda4451f7f3df35c6868
    summary: added CVE-2026-112457
    changed_fields:
      - content
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-112457
title: Apple Security Updates - October 2026
slug: 2026-10-apple-security-updates
description: Roundup of Apple security advisories published in October 2026.
date: "2026-10-26T23:47:50Z"
lastmod: "2026-10-27T01:52:47Z"
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
    product: macOS Golden Gate (< 27.2)
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-112457
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112457
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
  - at: "2026-10-27T01:52:47Z"
    level: L2
    summary: added CVE-2026-112457
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-112457
---

This roundup covers 3 Apple security vulnerabilities. CVSS base scores range from 7.8 to 8.8. None are reported as actively exploited at the time of release. The issues affect macOS, macOS Golden Gate.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-112427](#cve-2026-112427) | n/a | High | 8.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-112427) (authoritative) |
| [CVE-2026-112438](#cve-2026-112438) | macOS | High | 8.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-112438) (authoritative) |
| [CVE-2026-112484](#cve-2026-112484) | macOS Golden Gate (< 27.2) | High | 7.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-112484) (authoritative) |


## CVE-2026-112427

CVE-2026-112427 is an authentication vulnerability in macOS Golden Gate due to improper state management. A remote attacker could exploit this flaw to achieve arbitrary code execution on the target system.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-112427

## CVE-2026-112438

A logic vulnerability in macOS versions Golden Gate 27.2, Sequoia 15.8.2, and Tahoe 26.7.2 allows an unprivileged attacker to perform privilege escalation and execute arbitrary code as root by exploiting improved state management flaws.

Affected products:
- macOS

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-112438

## CVE-2026-112484

CVE-2026-112484 is a vulnerability in macOS resulting from improper file handling. An attacker capable of executing a malicious application on the target system can leverage this flaw to elevate privileges and execute arbitrary code with system-level permissions.

Affected products:
- macOS Golden Gate (< 27.2)
- macOS Sequoia (< 15.8.2)
- macOS Tahoe (< 26.7.2)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-112484
