---
title: Siemens Security Updates - October 2026
slug: 2026-10-siemens-security-updates
description: Roundup of Siemens security advisories published in October 2026.
date: "2026-10-13T10:34:38Z"
lastmod: "2026-10-13T10:35:11Z"
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
    cvss: 9.6
  - id: CVE-2026-63354
    product: S7-1500
    cvss: 9.6
  - id: CVE-2026-102073
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102074
updates:
  - at: "2026-10-13T10:34:38Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-63353
  - at: "2026-10-13T10:34:42Z"
    level: L2
    summary: added CVE-2026-63354
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-63354
  - at: "2026-10-13T10:35:11Z"
    level: L2
    summary: added CVE-2026-102073
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-102074
---

This roundup covers 3 Siemens security vulnerabilities. All have a CVSS base score of 9.6. None are reported as actively exploited at the time of release. The issues affect APOGEE MBC, S7-1500, SIMATIC S7-1500.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-63353](#cve-2026-63353) | SIMATIC S7-1500 | Critical | 9.6 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-63353) (authoritative) |
| [CVE-2026-63354](#cve-2026-63354) | S7-1500 | Critical | 9.6 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-63354) (authoritative) |
| [CVE-2026-102073](#cve-2026-102073) | APOGEE MBC (PPC) (BACnet) (All versions) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-102073) (authoritative) |


## CVE-2026-63353

CVE-2026-63353 is a stored cross-site scripting (XSS) vulnerability in the Trace file import functionality of affected industrial devices. An attacker can craft a malicious trace file containing JavaScript in the comment fields, which executes in the context of an authorized user's browser when viewed on the Trace page. This allows the attacker to hijack the user's session and perform unauthorized PLC operations via the web interface.

Affected products:
- SIMATIC S7-1500

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-63353

## CVE-2026-63354

A vulnerability in the processing of imported CSV trace files allows for stored cross-site scripting (XSS). An attacker can supply a specially crafted CSV file containing malicious JavaScript, which executes in the context of an authenticated user's browser session upon viewing the Trace page. This enables the attacker to perform unauthorized PLC operations via the web interface within the scope of the victim's privileges.

Affected products:
- S7-1500

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-63354

## CVE-2026-102073

The web service component in several Siemens APOGEE and TALON building automation controllers fails to properly validate the length of user-controllable input. This vulnerability allows an unauthenticated remote attacker to perform out-of-bounds memory reads or trigger a denial-of-service condition.

Affected products:
- APOGEE MBC (PPC) (BACnet) (All versions)
- APOGEE MBC (PPC) (P2 Ethernet) (All versions)
- APOGEE MEC (PPC) (BACnet) (All versions)
- APOGEE MEC (PPC) (P2 Ethernet) (All versions)
- APOGEE PXC Compact (BACnet) (< V3.5.7)
- APOGEE PXC Compact (P2 Ethernet) (< V2.8.21)
- APOGEE PXC Modular (BACnet) (< V3.5.7)
- APOGEE PXC Modular (P2 Ethernet) (< V2.8.21)
- TALON TC Compact (BACnet) (< V3.5.7)
- TALON TC Modular (BACnet) (< V3.5.7)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-102073
