---
brief_id: brief-2026-11-oracle-security-updates
event_id: brief-2026-11-oracle-security-updates
revision: 8
activity_at: "2026-11-18T03:09:10Z"
revision_history:
  - revision: 2
    at: "2026-11-17T23:49:55Z"
    checksum: sha256:f0ffe17bfc90d25e623a1962745b96cb36163a8ca9269d947ab1177163d93166
    summary: added CVE-2026-101663
    changed_fields:
      - claim_state
      - cpes
      - cve_verification
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101663
  - revision: 3
    at: "2026-11-18T01:20:26Z"
    checksum: sha256:b8098788f97775a834de109a5d9b2923de780fc68005343541f802e62d03ddbc
    summary: added CVE-2026-127308
    changed_fields:
      - content
      - cve_verification
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-127308
  - revision: 4
    at: "2026-11-18T01:36:18Z"
    checksum: sha256:76be0a6b35e137bf0d76ebf9f220beb4ee5660d0ea4bdd4f58f607563d2730b5
    summary: added CVE-2026-91516
    changed_fields:
      - content
      - cve_verification
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-91516
  - revision: 5
    at: "2026-11-18T01:42:33Z"
    checksum: sha256:055f14bd10e58b5718fd32d1d82aff06c443d28756727681f9d3cef966972344
    summary: added CVE-2026-91516
    changed_fields:
      - content
      - cves
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-91516
  - revision: 6
    at: "2026-11-18T02:27:52Z"
    checksum: sha256:6f6334ed9b731ae858e0de756af143ee7aad39eae88c0ba3effb4de17f05340d
    summary: added CVE-2026-127331
    changed_fields:
      - cve_verification
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-127331
  - revision: 7
    at: "2026-11-18T02:36:44Z"
    checksum: sha256:5da15a87fbbafe7441d2d448b5aa7e4fefb8501e8a5440501e9c4064f1cdbb9b
    summary: added CVE-2026-127331
    changed_fields:
      - content
      - cves
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-127331
  - revision: 8
    at: "2026-11-18T03:09:10Z"
    checksum: sha256:51084d8eb14eca9dbadc988e1b8ca93d7258146f33d36c851411b7f8527d115f
    summary: added CVE-2026-114887
    changed_fields:
      - cve_verification
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-114887
title: Oracle Security Updates - November 2026
slug: 2026-11-oracle-security-updates
description: Roundup of Oracle security advisories published in November 2026.
date: "2026-11-16T21:54:15Z"
lastmod: "2026-11-18T03:08:53Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:oracle:mobile_field_service:*:*:*:*:*:*:*:*
tags:
  - roundup
vendors:
  - Oracle
cve_verification:
  CVE-2026-91516:
    status: verified
    source: nvd
    checked_at: 2026-11-18T01:35:34.16788507Z
  CVE-2026-101653:
    status: verified
    source: nvd
    checked_at: 2026-11-17T23:49:08.738443818Z
  CVE-2026-101663:
    status: verified
    source: nvd
    checked_at: 2026-11-17T23:49:08.956701354Z
  CVE-2026-114887:
    status: verified
    source: nvd
    checked_at: 2026-11-18T03:08:52.843528271Z
  CVE-2026-127308:
    status: verified
    source: nvd
    checked_at: 2026-11-18T01:20:09.435826076Z
  CVE-2026-127331:
    status: verified
    source: nvd
    checked_at: 2026-11-18T02:27:32.433726999Z
cves:
  - id: CVE-2026-101653
    cvss: 8.8
    epss: 0.00433
    kev_status: "false"
  - id: CVE-2026-101663
    product: Oracle Mobile Field Service (12.2.3-12.2.15)
    cvss: 7.4
    kev_status: "false"
  - id: CVE-2026-127308
    product: AutoVue (21.1.0)
    cvss: 8.1
    kev_status: "false"
  - id: CVE-2026-91516
    product: Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0)
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-127331
    product: AutoVue (21.1.0)
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-114887
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114887
updates:
  - at: "2026-11-17T23:49:09Z"
    level: L2
    summary: added CVE-2026-101663
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101663
  - at: "2026-11-18T01:20:09Z"
    level: L2
    summary: added CVE-2026-127308
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-127308
  - at: "2026-11-18T01:35:34Z"
    level: L2
    summary: added CVE-2026-91516
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-91516
  - at: "2026-11-18T02:27:32Z"
    level: L2
    summary: added CVE-2026-127331
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-127331
  - at: "2026-11-18T03:08:53Z"
    level: L2
    summary: added CVE-2026-114887
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-114887
---

## Overview

This roundup covers 5 Oracle security vulnerabilities. CVSS base scores range from 7.4 to 8.8. None are reported as actively exploited at the time of release. The issues affect AutoVue, Oracle Access Manager, Oracle Mobile Field Service.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-101653](#cve-2026-101653) | n/a | High | 8.8 | 0.43% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-101653) (authoritative) |
| [CVE-2026-101663](#cve-2026-101663) | Oracle Mobile Field Service (12.2.3-12.2.15) | High | 7.4 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-101663) (authoritative) |
| [CVE-2026-127308](#cve-2026-127308) | AutoVue (21.1.0) | High | 8.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-127308) (authoritative) |
| [CVE-2026-91516](#cve-2026-91516) | Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0) | High | 7.5 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-91516) (authoritative) |
| [CVE-2026-127331](#cve-2026-127331) | AutoVue (21.1.0) | High | 7.5 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-127331) (authoritative) |


## By product

- **AutoVue**: [CVE-2026-127308](#cve-2026-127308), [CVE-2026-127331](#cve-2026-127331)

## Recommendation

Review affected products and apply Oracle's November 2026 security updates.

## CVE-2026-101653

Oracle Mobile Field Service, a component of Oracle E-Business Suite, contains a vulnerability in its Internal Operations module. The flaw allows a low-privileged, network-adjacent attacker using HTTPS to achieve a full takeover of the application. The vulnerability carries a CVSS 3.1 base score of 8.8, indicating high impact on confidentiality, integrity, and availability.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-101653

## CVE-2026-101663

Oracle Mobile Field Service within Oracle E-Business Suite (versions 12.2.3 through 12.2.15) contains a vulnerability in the Admin UI component. The vulnerability is remotely exploitable by an unauthenticated attacker via HTTP, potentially leading to unauthorized access, modification, or deletion of critical data.

Affected products:
- Oracle Mobile Field Service (12.2.3-12.2.15)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-101663

## CVE-2026-127308

CVE-2026-127308 is a vulnerability in the Security component of Oracle AutoVue version 21.1.0. An unauthenticated attacker can leverage this network-accessible flaw via HTTP to gain unauthorized access to or modify critical data. The attack requires human interaction, and the vulnerability carries a CVSS 3.1 base score of 8.1.

Affected products:
- AutoVue (21.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-127308

## CVE-2026-91516

CVE-2026-91516 is a high-severity denial-of-service vulnerability in the Authentication Engine of Oracle Access Manager versions 12.2.1.4.0 and 14.1.2.1.0. An unauthenticated remote attacker can exploit this flaw over TCP to cause the application to hang or crash, resulting in a complete loss of availability. The vulnerability is network-accessible and does not require user interaction or high privileges.

Affected products:
- Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-91516

## CVE-2026-127331

CVE-2026-127331 is a vulnerability in the Security component of Oracle AutoVue version 21.1.0. It allows an unauthenticated remote attacker to cause a denial-of-service (hang or crash) via HTTP network access. The vulnerability is characterized by a CVSS 3.1 base score of 7.5, indicating a high impact on system availability.

Affected products:
- AutoVue (21.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-127331
