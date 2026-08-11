---
title: SAP Security Updates - August 2026
slug: 2026-08-sap-security-updates
description: Roundup of SAP security advisories published in August 2026.
date: "2026-08-11T01:36:23Z"
lastmod: "2026-08-11T01:37:04Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - roundup
vendors:
  - SAP
products:
  - Manufacturing Integration and Intelligence (MII)
  - Manufacturing Integration and Intelligence
cves:
  - id: CVE-2026-34265
    cvss: 9.8
  - id: CVE-2026-44758
    cvss: 9.1
  - id: CVE-2026-44763
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44758
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44763
updates:
  - at: "2026-08-11T01:36:23Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-34265
  - at: "2026-08-11T01:36:40Z"
    level: L2
    summary: added CVE-2026-44758
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-44758
  - at: "2026-08-11T01:37:04Z"
    level: L2
    summary: added CVE-2026-44763
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-44763
---

This roundup covers 2 SAP security vulnerabilities. CVSS base scores range from 9.1 to 9.8. None are reported as actively exploited at the time of release. The issues affect Manufacturing Integration and Intelligence, NetWeaver Application Server ABAP.

## Summary

| CVE | CVSS | Product | Summary |
|-----|------|---------|---------|
| CVE-2026-34265 | 9.8 | NetWeaver Application Server ABAP | CVE-2026-34265 is a critical vulnerability in the SAP NetWeaver Application Server ABAP DIAG protocol parsing logic. An unauthenticated attacker can exploit this flaw to cause memory corruption, potentially leading to unauthorized disclosure of sensitive system information or a denial-of-service condition affecting system availability. |
| CVE-2026-44758 | 9.1 | Manufacturing Integration and Intelligence (MII) | SAP Manufacturing Integration and Intelligence (MII) is susceptible to a command injection vulnerability due to insufficient input validation. An attacker with high-level privileges can supply crafted input that results in arbitrary operating system command execution, potentially compromising the confidentiality, integrity, and availability of the affected system. |


## CVE-2026-34265

CVE-2026-34265 is a critical vulnerability in the SAP NetWeaver Application Server ABAP DIAG protocol parsing logic. An unauthenticated attacker can exploit this flaw to cause memory corruption, potentially leading to unauthorized disclosure of sensitive system information or a denial-of-service condition affecting system availability.

Affected products:
- NetWeaver Application Server ABAP

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-34265

## CVE-2026-44758

SAP Manufacturing Integration and Intelligence (MII) is susceptible to a command injection vulnerability due to insufficient input validation. An attacker with high-level privileges can supply crafted input that results in arbitrary operating system command execution, potentially compromising the confidentiality, integrity, and availability of the affected system.

Affected products:
- Manufacturing Integration and Intelligence (MII)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-44758
