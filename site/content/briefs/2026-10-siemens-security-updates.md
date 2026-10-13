---
title: Siemens Security Updates - October 2026
slug: 2026-10-siemens-security-updates
description: Roundup of Siemens security advisories published in October 2026.
date: "2026-10-13T10:34:38Z"
lastmod: "2026-10-13T10:35:31Z"
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
  - id: CVE-2026-102074
    cvss: 7.5
  - id: CVE-2026-102075
    cvss: 7.5
  - id: CVE-2026-102076
    cvss: 7.5
  - id: CVE-2026-59241
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78557
updates:
  - at: "2026-10-13T10:35:11Z"
    level: L2
    summary: added CVE-2026-102073 +4
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-102074
      - https://nvd.nist.gov/vuln/detail/CVE-2026-102075
      - https://nvd.nist.gov/vuln/detail/CVE-2026-59241
      - https://nvd.nist.gov/vuln/detail/CVE-2026-72895
      - https://nvd.nist.gov/vuln/detail/CVE-2026-78557
---

This roundup covers 9 Siemens security vulnerabilities. CVSS base scores range from 7.5 to 9.6. None are reported as actively exploited at the time of release. The issues affect APOGEE MBC, Industrial Edge App Publisher, S7-1500, SIMATIC IPC BX-21A, SIMATIC S7-1500, SIMATIC WinCC.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-63353](#cve-2026-63353) | SIMATIC S7-1500 | Critical | 9.6 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-63353) (authoritative) |
| [CVE-2026-63354](#cve-2026-63354) | S7-1500 | Critical | 9.6 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-63354) (authoritative) |
| [CVE-2026-102073](#cve-2026-102073) | APOGEE MBC (PPC) (BACnet) (All versions) | High | 8.2 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-102073) (authoritative) |
| [CVE-2026-102074](#cve-2026-102074) | APOGEE MBC (PPC) (BACnet) (All versions) | High | 7.5 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-102074) (authoritative) |
| [CVE-2026-102075](#cve-2026-102075) | APOGEE MBC (PPC) (BACnet) (All versions) | High | 7.5 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-102075) (authoritative) |
| [CVE-2026-102076](#cve-2026-102076) | APOGEE MBC (PPC) (BACnet) (All versions) | High | 7.5 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-102076) (authoritative) |
| [CVE-2026-59241](#cve-2026-59241) | SIMATIC WinCC (V7.5) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-59241) (authoritative) |
| [CVE-2026-72895](#cve-2026-72895) | SIMATIC IPC BX-21A (< V31.01.13) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-72895) (authoritative) |
| [CVE-2026-78556](#cve-2026-78556) | Industrial Edge App Publisher (< V1.27.9) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-78556) (authoritative) |


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






Related in this roundup: [CVE-2026-102074](#cve-2026-102074), [CVE-2026-102075](#cve-2026-102075), [CVE-2026-102076](#cve-2026-102076).

## CVE-2026-102074

A vulnerability in the FTP service of various Siemens APOGEE and TALON building automation controllers allows an unauthenticated remote attacker to trigger a denial of service condition. The flaw stems from improper input length validation, which can be exploited by sending specially crafted inputs to the affected devices.

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

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-102074






Related in this roundup: [CVE-2026-102073](#cve-2026-102073), [CVE-2026-102075](#cve-2026-102075), [CVE-2026-102076](#cve-2026-102076).

## CVE-2026-102075

A vulnerability in the web service of multiple Siemens APOGEE and TALON automation controllers stems from improper validation of user input during multipart handling. An unauthenticated remote attacker could exploit this flaw to trigger a denial of service condition.

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

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-102075





Related in this roundup: [CVE-2026-102073](#cve-2026-102073), [CVE-2026-102074](#cve-2026-102074), [CVE-2026-102076](#cve-2026-102076).

## CVE-2026-102076

A vulnerability in the web service of various Siemens APOGEE and TALON building automation controllers exists due to improper validation of user-supplied input during file uploads. An unauthenticated remote attacker can exploit this flaw to trigger a denial of service condition on the affected devices.

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

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-102076




Related in this roundup: [CVE-2026-102073](#cve-2026-102073), [CVE-2026-102074](#cve-2026-102074), [CVE-2026-102075](#cve-2026-102075).

## CVE-2026-59241

Siemens SIMATIC WinCC contains a privilege escalation vulnerability due to insufficiently restricted permissions on a database role. An authenticated remote attacker with database access can exploit this flaw to execute arbitrary commands on the underlying host system, leading to full system compromise.

Affected products:
- SIMATIC WinCC (V7.5)
- SIMATIC WinCC (V8.0 < Update 11)
- SIMATIC WinCC (V8.1 < Update 7)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-59241

## CVE-2026-72895

Siemens SIMATIC IPC devices contain a BIOS vendor test key within the UEFI Secure Boot database. A local attacker with physical or administrative access can leverage this key to sign and execute unauthorized operating systems or UEFI applications, effectively bypassing Secure Boot protections. Successful exploitation leads to a compromise of device integrity and confidentiality.

Affected products:
- SIMATIC IPC BX-21A (< V31.01.13)
- SIMATIC IPC RW-543A (< V1.1.4)
- SIMATIC IPC227G (< V28.01.15)
- SIMATIC IPC277G (< V28.01.15)
- SIMATIC IPC277G PRO (< V28.01.15)
- SIMATIC IPC327G (< V28.01.15)
- SIMATIC IPC377G (< V28.01.15)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-72895

## CVE-2026-78556

Industrial Edge App Publisher versions prior to V1.27.9 are vulnerable to a man-in-the-middle (MitM) attack due to improper server certificate validation during TLS connection initiation. An attacker can exploit this flaw to intercept, relay, or spoof communication between the client and the intended server.

Affected products:
- Industrial Edge App Publisher (< V1.27.9)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-78556
