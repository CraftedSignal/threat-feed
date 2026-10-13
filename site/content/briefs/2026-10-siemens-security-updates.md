---
title: Siemens Security Updates - October 2026
slug: 2026-10-siemens-security-updates
description: Roundup of Siemens security advisories published in October 2026.
date: "2026-10-13T10:34:38Z"
lastmod: "2026-10-13T10:34:38Z"
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
  - id: CVE-2026-63353
    product: SIMATIC S7-1500
updates:
  - at: "2026-10-13T10:34:38Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-63353
---

This roundup covers 1 Siemens security vulnerabilities. None are reported as actively exploited at the time of release. The issues affect SIMATIC S7-1500.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-63353](#cve-2026-63353) | SIMATIC S7-1500 |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-63353) (authoritative) |


## CVE-2026-63353

CVE-2026-63353 is a stored cross-site scripting (XSS) vulnerability in the Trace file import functionality of affected industrial devices. An attacker can craft a malicious trace file containing JavaScript in the comment fields, which executes in the context of an authorized user's browser when viewed on the Trace page. This allows the attacker to hijack the user's session and perform unauthorized PLC operations via the web interface.

Affected products:
- SIMATIC S7-1500

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-63353
