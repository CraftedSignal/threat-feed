---
title: SAP Security Updates - September 2026
slug: 2026-09-sap-security-updates
description: Roundup of SAP security advisories published in September 2026.
date: "2026-09-08T01:38:00Z"
lastmod: "2026-09-08T01:38:23Z"
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
  - id: CVE-2026-58240
    product: NetWeaver Message Server
    cvss: 9.8
  - id: CVE-2026-66768
    product: SAP GUI for Java
    cvss: 9
  - id: CVE-2026-76969
    product: '@sap/cds-mtxs'
    cvss: 9.4
  - id: CVE-2026-66767
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66767
updates:
  - at: "2026-09-08T01:38:00Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-58240
  - at: "2026-09-08T01:38:03Z"
    level: L2
    summary: added CVE-2026-66767, CVE-2026-66768, CVE-2026-76969
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-66768
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76969
      - https://nvd.nist.gov/vuln/detail/CVE-2026-66767
---

This roundup covers 3 SAP security vulnerabilities. CVSS base scores range from 9.0 to 9.8. None are reported as actively exploited at the time of release. The issues affect @sap/cds-mtxs, NetWeaver Message Server, SAP GUI for Java.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-58240](#cve-2026-58240) | NetWeaver Message Server | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-58240) (authoritative) |
| [CVE-2026-66768](#cve-2026-66768) | SAP GUI for Java | Critical | 9.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-66768) (authoritative) |
| [CVE-2026-76969](#cve-2026-76969) | @sap/cds-mtxs | Critical | 9.4 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76969) (authoritative) |


## CVE-2026-58240

SAP NetWeaver Message Server contains a vulnerability where it fails to properly validate the authenticity of internal application server components during registration. An unauthenticated attacker with network access can exploit this to register unauthorized components, leading to potential unauthorized actions, data compromise, and system instability.

Affected products:
- NetWeaver Message Server

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-58240

## CVE-2026-66768

SAP GUI for Java fails to properly enforce trust level policies when handling requests from a backend system. A low-privileged attacker who compromises or manipulates the backend can trigger these functions to execute arbitrary commands on the client machine running SAP GUI, resulting in a full compromise of the local environment.

Affected products:
- SAP GUI for Java

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-66768

## CVE-2026-76969

The @sap/cds-mtxs NPM library contains a vulnerability in multitenant CAP applications where insufficient checks on extensibility functionality allow unauthenticated remote attackers to obtain sensitive credentials. These credentials can then be used to manipulate or delete tenant data, resulting in significant impact to data integrity and service availability.

Affected products:
- @sap/cds-mtxs

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76969
