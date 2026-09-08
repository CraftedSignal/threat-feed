---
title: SAP Security Updates - September 2026
slug: 2026-09-sap-security-updates
description: Roundup of SAP security advisories published in September 2026.
date: "2026-09-08T01:38:00Z"
lastmod: "2026-09-08T01:38:03Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - roundup
vendors:
  - SAP
cves:
  - id: CVE-2026-58240
    product: NetWeaver Message Server
    cvss: 9.8
  - id: CVE-2026-66768
    cvss: 9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66768
updates:
  - at: "2026-09-08T01:38:00Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-58240
  - at: "2026-09-08T01:38:03Z"
    level: L2
    summary: added CVE-2026-66768
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-66768
---

This roundup covers 1 SAP security vulnerabilities. None are reported as actively exploited at the time of release. The issues affect NetWeaver Message Server.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-58240](#cve-2026-58240) | NetWeaver Message Server |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-58240) (authoritative) |


## CVE-2026-58240

SAP NetWeaver Message Server contains a vulnerability where it fails to properly validate the authenticity of internal application server components during registration. An unauthenticated attacker with network access can exploit this to register unauthorized components, leading to potential unauthorized actions, data compromise, and system instability.

Affected products:
- NetWeaver Message Server

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-58240
