---
title: SAP Security Updates - October 2026
slug: 2026-10-sap-security-updates
description: Roundup of SAP security advisories published in October 2026.
date: "2026-10-13T02:31:31Z"
lastmod: "2026-10-13T02:31:33Z"
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
  - id: CVE-2026-89107
    product: S/4HANA
    cvss: 9.9
  - id: CVE-2026-89108
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89108
updates:
  - at: "2026-10-13T02:31:31Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-89107
  - at: "2026-10-13T02:31:33Z"
    level: L2
    summary: added CVE-2026-89108
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-89108
---

This roundup covers 1 SAP security vulnerabilities. None are reported as actively exploited at the time of release. The issues affect S/4HANA.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-89107](#cve-2026-89107) | S/4HANA |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-89107) (authoritative) |


## CVE-2026-89107

SAP S/4HANA's 'Manage Substitution/Validation Rules' feature contains a vulnerability where input provided to a domain-specific scripting language is not sufficiently validated. An authenticated attacker with specific privileges can submit crafted input that is interpreted as executable ABAP code, leading to arbitrary code execution and full system compromise.

Affected products:
- S/4HANA

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-89107
