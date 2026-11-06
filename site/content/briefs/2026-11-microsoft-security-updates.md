---
brief_id: brief-2026-11-microsoft-security-updates
event_id: brief-2026-11-microsoft-security-updates
revision: 1
activity_at: "2026-11-02T21:54:23Z"
title: Microsoft Security Updates - November 2026
slug: 2026-11-microsoft-security-updates
description: Roundup of Microsoft security advisories published in November 2026.
date: "2026-11-02T21:54:23Z"
lastmod: "2026-11-06T23:27:44Z"
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
  - Microsoft
cves:
  - id: CVE-2026-58934
    product: Windows
    cvss: 8.4
    epss: 0.0011
    kev_status: "false"
  - id: CVE-2026-109469
    cvss: 10
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109469
updates:
  - at: "2026-11-02T21:54:23Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-58934
  - at: "2026-11-06T23:27:44Z"
    level: L2
    summary: added CVE-2026-109469
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-109469
---

This roundup covers 1 Microsoft security vulnerabilities. None are reported as actively exploited at the time of release. The issues affect Windows.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-58934](#cve-2026-58934) | Windows |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-58934) (authoritative) |


## CVE-2026-58934

CVE-2026-58934 describes a logic error in the prepareWindowToDisplayDuringRelayout function within WindowState.java, which enables a local privilege escalation vulnerability. The flaw allows an attacker to bypass permission checks without requiring additional execution privileges or user interaction.

Affected products:
- Windows

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-58934
