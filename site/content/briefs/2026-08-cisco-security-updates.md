---
title: Cisco Security Updates - August 2026
slug: 2026-08-cisco-security-updates
description: Roundup of Cisco security advisories published in August 2026.
date: "2026-08-05T17:20:12Z"
lastmod: "2026-08-05T17:20:55Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - roundup
vendors:
  - Cisco
products:
  - IOS XE Software
  - Catalyst SD-WAN
  - Integrated Management Controller
cves:
  - id: CVE-2026-20267
    cvss: 9
  - id: CVE-2026-20272
    cvss: 9.8
  - id: CVE-2026-20310
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20272
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20310
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20124
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20200
updates:
  - at: "2026-08-05T17:20:12Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20267
  - at: "2026-08-05T17:20:14Z"
    level: L2
    summary: added CVE-2026-20272, CVE-2026-20310
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20272
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20310
  - at: "2026-08-05T17:20:55Z"
    level: L1
    summary: new product
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20200
---

This roundup covers 4 Cisco security vulnerabilities. None are reported as actively exploited at the time of release. The issues affect Catalyst SD-WAN, IOS XE Software.

## Summary

| CVE | CVSS | Product | Summary |
|-----|------|---------|---------|
| CVE-2026-20267 | 9.0 | IOS XE Software | Cisco IOS XE Software contains multiple internally discovered vulnerabilities characterized by improper access control (CWE-284). These vulnerabilities were identified during an internal security review and addressed through software hardening releases, carrying a CVSS base score of 9.0. |
| CVE-2026-20272 | 9.8 | IOS XE Software | CVE-2026-20272 represents a critical vulnerability in Cisco IOS XE Software, identified through internal security reviews as an issue involving improper neutralization of special elements, classified under CWE-74. With a CVSS base score of 9.8, the vulnerability allows for potential remote command injection, requiring immediate patching as part of Cisco's software hardening releases. |
| CVE-2026-20310 | 9.1 | Catalyst SD-WAN | Cisco Catalyst SD-WAN is affected by a vulnerability (CVE-2026-20310) resulting from improper link resolution before file access, categorized as CWE-59. This internally discovered issue prompted security hardening updates for the affected platform. |
| CVE-2026-20124 | 0.0 | IOS XE Software | CVE-2026-20124 is a denial of service vulnerability in the SNMP subsystem of Cisco IOS XE Software. An authenticated remote attacker with valid SNMP community strings (v1/v2c) or credentials (v3) can send a malformed SNMP request, causing the device to unexpectedly reload. Detection should focus on monitoring SNMP request traffic for anomalies or malformed packets targeting the SNMP subsystem. |


## CVE-2026-20267

Cisco IOS XE Software contains multiple internally discovered vulnerabilities characterized by improper access control (CWE-284). These vulnerabilities were identified during an internal security review and addressed through software hardening releases, carrying a CVSS base score of 9.0.

Affected products:
- IOS XE Software

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20267

## CVE-2026-20272

CVE-2026-20272 represents a critical vulnerability in Cisco IOS XE Software, identified through internal security reviews as an issue involving improper neutralization of special elements, classified under CWE-74. With a CVSS base score of 9.8, the vulnerability allows for potential remote command injection, requiring immediate patching as part of Cisco's software hardening releases.

Affected products:
- IOS XE Software

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20272

## CVE-2026-20310

Cisco Catalyst SD-WAN is affected by a vulnerability (CVE-2026-20310) resulting from improper link resolution before file access, categorized as CWE-59. This internally discovered issue prompted security hardening updates for the affected platform.

Affected products:
- Catalyst SD-WAN

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20310

## CVE-2026-20124

CVE-2026-20124 is a denial of service vulnerability in the SNMP subsystem of Cisco IOS XE Software. An authenticated remote attacker with valid SNMP community strings (v1/v2c) or credentials (v3) can send a malformed SNMP request, causing the device to unexpectedly reload. Detection should focus on monitoring SNMP request traffic for anomalies or malformed packets targeting the SNMP subsystem.

Affected products:
- IOS XE Software

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20124
