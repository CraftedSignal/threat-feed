---
title: Cisco Security Updates - August 2026
slug: 2026-08-cisco-security-updates
description: Roundup of Cisco security advisories published in August 2026.
date: "2026-08-05T17:20:12Z"
lastmod: "2026-08-05T17:21:13Z"
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
  - IOS Software
cves:
  - id: CVE-2026-20267
    cvss: 9
  - id: CVE-2026-20272
    cvss: 9.8
  - id: CVE-2026-20310
    cvss: 9.1
  - id: CVE-2026-20200
    cvss: 8.8
  - id: CVE-2026-20263
    cvss: 8.6
  - id: CVE-2026-20268
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20272
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20310
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20124
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20200
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20263
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20268
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20269
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20271
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20273
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20301
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20312
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20313
updates:
  - at: "2026-08-05T17:20:18Z"
    level: L2
    summary: added CVE-2026-20310
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20310
  - at: "2026-08-05T17:20:55Z"
    level: L1
    summary: new product
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20200
  - at: "2026-08-05T17:21:01Z"
    level: L2
    summary: added CVE-2026-20200, CVE-2026-20263, CVE-2026-20268
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20269
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20301
      - https://nvd.nist.gov/vuln/detail/CVE-2026-20313
---

This roundup covers 12 Cisco security vulnerabilities. None are reported as actively exploited at the time of release. The issues affect Catalyst SD-WAN, IOS Software, IOS XE Software, Integrated Management Controller.

## Summary

| CVE | CVSS | Product | Summary |
|-----|------|---------|---------|
| CVE-2026-20267 | 9.0 | IOS XE Software | Cisco IOS XE Software contains multiple internally discovered vulnerabilities characterized by improper access control (CWE-284). These vulnerabilities were identified during an internal security review and addressed through software hardening releases, carrying a CVSS base score of 9.0. |
| CVE-2026-20272 | 9.8 | IOS XE Software | CVE-2026-20272 represents a critical vulnerability in Cisco IOS XE Software, identified through internal security reviews as an issue involving improper neutralization of special elements, classified under CWE-74. With a CVSS base score of 9.8, the vulnerability allows for potential remote command injection, requiring immediate patching as part of Cisco's software hardening releases. |
| CVE-2026-20310 | 9.1 | Catalyst SD-WAN | Cisco Catalyst SD-WAN is affected by a vulnerability (CVE-2026-20310) resulting from improper link resolution before file access, categorized as CWE-59. This internally discovered issue prompted security hardening updates for the affected platform. |
| CVE-2026-20124 | 0.0 | IOS XE Software | CVE-2026-20124 is a denial of service vulnerability in the SNMP subsystem of Cisco IOS XE Software. An authenticated remote attacker with valid SNMP community strings (v1/v2c) or credentials (v3) can send a malformed SNMP request, causing the device to unexpectedly reload. Detection should focus on monitoring SNMP request traffic for anomalies or malformed packets targeting the SNMP subsystem. |
| CVE-2026-20200 | 8.8 | Integrated Management Controller | Cisco IMC contains a vulnerability in its web-based management interface stemming from improper input validation. An authenticated remote attacker with low privileges can leverage this flaw to perform command injection, resulting in the execution of arbitrary commands with root-level privileges on the underlying operating system. |
| CVE-2026-20263 | 0.0 | IOS XE Software | A vulnerability in the Blocks Extensible Exchange Protocol (BEEP) feature of Cisco IOS XE Software allows unauthenticated remote attackers to trigger a device reload via a crafted BEEP SOAP request, resulting in a denial-of-service (DoS) condition. |
| CVE-2026-20268 | 8.6 | IOS XE Software | Cisco IOS XE Software contains vulnerabilities related to improper restriction of operations within the bounds of a memory buffer, categorized under CWE-119. These issues were discovered during an internal security review and addressed via software hardening releases, carrying a CVSS v3.1 base score of 8.6. |
| CVE-2026-20269 | 0.0 | IOS XE Software | Cisco IOS XE Software contains multiple internally discovered vulnerabilities related to improper control of a resource through its lifetime, classified under CWE-664. These issues were identified during a proactive internal security review and have been addressed in software hardening releases. |
| CVE-2026-20271 | 0.0 | IOS XE Software | Cisco IOS XE Software contains multiple vulnerabilities related to insufficient control flow management, categorized under CWE-691. These vulnerabilities were identified through an internal security review, and Cisco has released software updates to address the underlying issues. |
| CVE-2026-20273 | 0.0 | IOS XE Software | CVE-2026-20273 refers to an improper input validation vulnerability (CWE-20) in Cisco IOS XE Software. With a CVSS base score of 8.6, this vulnerability is exploitable remotely by an unauthenticated attacker, potentially leading to a denial-of-service condition (AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H). |
| CVE-2026-20301 | 0.0 | IOS Software | A vulnerability in the Extensible Messaging Client Protocol (XMCP) implementation within Cisco IOS and IOS XE software allows unauthenticated, remote attackers to trigger a device reload via malformed packets, resulting in a denial-of-service condition. |
| CVE-2026-20312 | 0.0 | Catalyst SD-WAN | Cisco Catalyst SD-WAN software contains a vulnerability identified as CVE-2026-20312 involving the cleartext storage of sensitive information, classified under CWE-312. This vulnerability was identified during an internal security review and addressed through a software hardening release. |


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

## CVE-2026-20200

Cisco IMC contains a vulnerability in its web-based management interface stemming from improper input validation. An authenticated remote attacker with low privileges can leverage this flaw to perform command injection, resulting in the execution of arbitrary commands with root-level privileges on the underlying operating system.

Affected products:
- Integrated Management Controller

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20200

## CVE-2026-20263

A vulnerability in the Blocks Extensible Exchange Protocol (BEEP) feature of Cisco IOS XE Software allows unauthenticated remote attackers to trigger a device reload via a crafted BEEP SOAP request, resulting in a denial-of-service (DoS) condition.

Affected products:
- IOS XE Software

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20263

## CVE-2026-20268

Cisco IOS XE Software contains vulnerabilities related to improper restriction of operations within the bounds of a memory buffer, categorized under CWE-119. These issues were discovered during an internal security review and addressed via software hardening releases, carrying a CVSS v3.1 base score of 8.6.

Affected products:
- IOS XE Software

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20268

## CVE-2026-20269

Cisco IOS XE Software contains multiple internally discovered vulnerabilities related to improper control of a resource through its lifetime, classified under CWE-664. These issues were identified during a proactive internal security review and have been addressed in software hardening releases.

Affected products:
- IOS XE Software

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20269

## CVE-2026-20271

Cisco IOS XE Software contains multiple vulnerabilities related to insufficient control flow management, categorized under CWE-691. These vulnerabilities were identified through an internal security review, and Cisco has released software updates to address the underlying issues.

Affected products:
- IOS XE Software

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20271

## CVE-2026-20273

CVE-2026-20273 refers to an improper input validation vulnerability (CWE-20) in Cisco IOS XE Software. With a CVSS base score of 8.6, this vulnerability is exploitable remotely by an unauthenticated attacker, potentially leading to a denial-of-service condition (AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H).

Affected products:
- IOS XE Software

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20273

## CVE-2026-20301

A vulnerability in the Extensible Messaging Client Protocol (XMCP) implementation within Cisco IOS and IOS XE software allows unauthenticated, remote attackers to trigger a device reload via malformed packets, resulting in a denial-of-service condition.

Affected products:
- IOS Software
- IOS XE Software

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20301

## CVE-2026-20312

Cisco Catalyst SD-WAN software contains a vulnerability identified as CVE-2026-20312 involving the cleartext storage of sensitive information, classified under CWE-312. This vulnerability was identified during an internal security review and addressed through a software hardening release.

Affected products:
- Catalyst SD-WAN

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-20312
