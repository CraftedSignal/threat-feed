---
title: Qualcomm Security Updates - October 2026
slug: 2026-10-qualcomm-security-updates
description: Roundup of Qualcomm security advisories published in October 2026.
date: "2026-10-06T08:54:45Z"
lastmod: "2026-10-06T08:54:45Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - roundup
vendors:
  - Qualcomm
cves:
  - id: CVE-2026-57554
    product: FastRPC
updates:
  - at: "2026-10-06T08:54:45Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-57554
---

This roundup covers 1 Qualcomm security vulnerabilities. None are reported as actively exploited at the time of release. The issues affect FastRPC.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-57554](#cve-2026-57554) | FastRPC |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-57554) (authoritative) |


## CVE-2026-57554

CVE-2026-57554 involves a memory corruption vulnerability in the FastRPC implementation, triggered when asynchronous threads access shared performance counter data simultaneously. This flaw could potentially allow an attacker to escalate privileges or cause a denial of service.

Affected products:
- FastRPC

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-57554
