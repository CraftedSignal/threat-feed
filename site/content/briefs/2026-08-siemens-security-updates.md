---
title: Siemens Security Updates - August 2026
slug: 2026-08-siemens-security-updates
description: Roundup of Siemens security advisories published in August 2026.
date: "2026-08-11T14:02:04Z"
lastmod: "2026-08-11T14:02:25Z"
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
  - id: CVE-2026-58115
    product: SIMATIC IoT2050 Advanced (< V4.3.4.1)
    cvss: 10
  - id: CVE-2026-50058
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-50058
updates:
  - at: "2026-08-11T14:02:04Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-58115
  - at: "2026-08-11T14:02:25Z"
    level: L2
    summary: added CVE-2026-50058
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-50058
---

This roundup covers 1 Siemens security vulnerabilities. None are reported as actively exploited at the time of release. The issues affect SIMATIC IoT2050 Advanced.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-58115](#cve-2026-58115) | SIMATIC IoT2050 Advanced (< V4.3.4.1) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-58115) (authoritative) |


## CVE-2026-58115

Siemens SIMATIC IoT2050 Advanced devices running Industrial OS with Node-RED installed are vulnerable to unauthorized access due to a lack of authentication on the Node-RED HTTP interface. An unauthenticated remote attacker can exploit this flaw to deploy malicious flows, resulting in arbitrary code execution with root-level privileges on the target system.

Affected products:
- SIMATIC IoT2050 Advanced (< V4.3.4.1)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-58115
