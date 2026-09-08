---
title: Siemens Security Updates - September 2026
slug: 2026-09-siemens-security-updates
description: Roundup of Siemens security advisories published in September 2026.
date: "2026-09-08T09:40:10Z"
lastmod: "2026-09-08T09:40:10Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - roundup
vendors:
  - Siemens
cves:
  - id: CVE-2026-50093
    product: Siveillance Control Pro (< V3.0.12.2173)
updates:
  - at: "2026-09-08T09:40:10Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-50093
---

This roundup covers 1 Siemens security vulnerabilities. None are reported as actively exploited at the time of release. The issues affect Siveillance Control Pro.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-50093](#cve-2026-50093) | Siveillance Control Pro (< V3.0.12.2173) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-50093) (authoritative) |


## CVE-2026-50093

A vulnerability in the OIS web module of Siemens Siveillance Control and Siveillance Control Pro allows an unauthenticated remote attacker to perform arbitrary file uploads. Exploitation of this flaw can lead to remote code execution and the attainment of root-level privileges on the host system, resulting in a full compromise of the affected environment.

Affected products:
- Siveillance Control Pro (< V3.0.12.2173)
- Siveillance Control Pro (< V4.0.9.2178)
- Siveillance Control (< V3.0.22.2177)
- Siveillance Control (< V4.0.11.2177)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-50093
