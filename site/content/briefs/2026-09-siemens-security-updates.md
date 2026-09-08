---
title: Siemens Security Updates - September 2026
slug: 2026-09-siemens-security-updates
description: Roundup of Siemens security advisories published in September 2026.
date: "2026-09-08T09:40:10Z"
lastmod: "2026-09-08T09:40:22Z"
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
    cvss: 9
  - id: CVE-2026-62645
    product: Reyrolle 7SR5 (< V2.70)
    cvss: 9.8
  - id: CVE-2026-34223
    product: Desigo CC ClickOnce Client
    cvss: 8.2
  - id: CVE-2026-62646
    product: Reyrolle 7SR5 (< V2.70)
    cvss: 7.4
  - id: CVE-2026-62647
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62647
updates:
  - at: "2026-09-08T09:40:10Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-50093
  - at: "2026-09-08T09:40:14Z"
    level: L2
    summary: added CVE-2026-34223 +3
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-62645
      - https://nvd.nist.gov/vuln/detail/CVE-2026-34223
      - https://nvd.nist.gov/vuln/detail/CVE-2026-62646
      - https://nvd.nist.gov/vuln/detail/CVE-2026-62647
---

This roundup covers 4 Siemens security vulnerabilities. CVSS base scores range from 7.4 to 9.8. None are reported as actively exploited at the time of release. The issues affect Desigo CC ClickOnce Client, Reyrolle 7SR5, Siveillance Control Pro.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-50093](#cve-2026-50093) | Siveillance Control Pro (< V3.0.12.2173) | Critical | 9.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-50093) (authoritative) |
| [CVE-2026-62645](#cve-2026-62645) | Reyrolle 7SR5 (< V2.70) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-62645) (authoritative) |
| [CVE-2026-34223](#cve-2026-34223) | Desigo CC ClickOnce Client | High | 8.2 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-34223) (authoritative) |
| [CVE-2026-62646](#cve-2026-62646) | Reyrolle 7SR5 (< V2.70) | High | 7.4 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-62646) (authoritative) |


## CVE-2026-50093

A vulnerability in the OIS web module of Siemens Siveillance Control and Siveillance Control Pro allows an unauthenticated remote attacker to perform arbitrary file uploads. Exploitation of this flaw can lead to remote code execution and the attainment of root-level privileges on the host system, resulting in a full compromise of the affected environment.

Affected products:
- Siveillance Control Pro (< V3.0.12.2173)
- Siveillance Control Pro (< V4.0.9.2178)
- Siveillance Control (< V3.0.22.2177)
- Siveillance Control (< V4.0.11.2177)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-50093

## CVE-2026-62645

A vulnerability in the Reyrolle 7SR5 web interface allows for the calculation of valid session IDs due to weak session management. An attacker can exploit this to bypass authentication and gain unauthorized administrative access to the device, potentially leading to full control over the relay unit.

Affected products:
- Reyrolle 7SR5 (< V2.70)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-62645

Related in this roundup: [CVE-2026-62646](#cve-2026-62646).

## CVE-2026-34223

The Desigo CC family of products is vulnerable to arbitrary file write via a Client Code Execution (CCE) flaw triggered by insufficient input validation of scripts embedded in user-defined graphics documents. An attacker can craft a malicious document that, when opened by a privileged user, executes scripts to write arbitrary files to the host filesystem, potentially leading to full system compromise.

Affected products:
- Desigo CC ClickOnce Client
- Desigo CC family
- Desigo CC Flex Client
- Desigo CC Installed Client

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-34223

## CVE-2026-62646

A vulnerability in Siemens Reyrolle 7SR5 relays versions prior to V2.70 allows an unauthenticated remote attacker to predict or brute-force session identifiers due to insufficient entropy in the generation algorithm. This flaw permits session hijacking and authentication bypass.

Affected products:
- Reyrolle 7SR5 (< V2.70)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-62646

Related in this roundup: [CVE-2026-62645](#cve-2026-62645).
