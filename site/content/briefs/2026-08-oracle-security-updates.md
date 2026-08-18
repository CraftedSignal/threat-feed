---
title: Oracle Security Updates - August 2026
slug: 2026-08-oracle-security-updates
description: Roundup of Oracle security advisories published in August 2026.
date: "2026-08-18T22:56:20Z"
lastmod: "2026-08-18T22:56:31Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - roundup
vendors:
  - Oracle
cves:
  - id: CVE-2026-60591
    product: Hospitality Simphony (19.8-19.8.5, 19.9-19.9.3, 19.10-19.10.1)
    cvss: 9.1
  - id: CVE-2026-60672
    product: WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0)
    cvss: 9.8
  - id: CVE-2026-60696
    product: WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0)
    cvss: 9.8
  - id: CVE-2026-60698
    product: WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0)
    cvss: 9.8
  - id: CVE-2026-60702
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-60702
updates:
  - at: "2026-08-18T22:56:21Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-60591
  - at: "2026-08-18T22:56:23Z"
    level: L2
    summary: added CVE-2026-60672 +3
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-60672
      - https://nvd.nist.gov/vuln/detail/CVE-2026-60696
      - https://nvd.nist.gov/vuln/detail/CVE-2026-60698
      - https://nvd.nist.gov/vuln/detail/CVE-2026-60702
---

This roundup covers 4 Oracle security vulnerabilities. CVSS base scores range from 9.1 to 9.8. None are reported as actively exploited at the time of release. The issues affect Hospitality Simphony, WebLogic Server.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-60591](#cve-2026-60591) | Hospitality Simphony (19.8-19.8.5, 19.9-19.9.3, 19.10-19.10.1) | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60591) (authoritative) |
| [CVE-2026-60672](#cve-2026-60672) | WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60672) (authoritative) |
| [CVE-2026-60696](#cve-2026-60696) | WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60696) (authoritative) |
| [CVE-2026-60698](#cve-2026-60698) | WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60698) (authoritative) |


## CVE-2026-60591

Oracle Hospitality Simphony contains a high-severity vulnerability that allows an unauthenticated attacker to perform unauthorized data modification or deletion and trigger a denial-of-service condition via network-based HTTP requests. The vulnerability affects multiple versions of the POS component.

Affected products:
- Hospitality Simphony (19.8-19.8.5, 19.9-19.9.3, 19.10-19.10.1)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60591

## CVE-2026-60672

CVE-2026-60672 is a critical vulnerability in Oracle WebLogic Server (Core component) that allows an unauthenticated attacker with network access via T3 or IIOP protocols to achieve full server takeover. The vulnerability is remotely exploitable without user interaction and carries a CVSS base score of 9.8, indicating severe impact on confidentiality, integrity, and availability.

Affected products:
- WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60672


Related in this roundup: [CVE-2026-60696](#cve-2026-60696), [CVE-2026-60698](#cve-2026-60698).

## CVE-2026-60696

Oracle WebLogic Server contains a critical vulnerability in its Core component that allows unauthenticated, network-adjacent attackers to achieve full system takeover via T3 or IIOP protocols. The flaw is easily exploitable, requiring no user interaction or authentication, and impacts confidentiality, integrity, and availability.

Affected products:
- WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60696


Related in this roundup: [CVE-2026-60672](#cve-2026-60672), [CVE-2026-60698](#cve-2026-60698).

## CVE-2026-60698

CVE-2026-60698 is a critical vulnerability affecting the Core component of Oracle WebLogic Server. An unauthenticated attacker can exploit this via the IIOP protocol over the network to achieve full system takeover. The vulnerability carries a CVSS 3.1 score of 9.8 and impacts the confidentiality, integrity, and availability of the affected server.

Affected products:
- WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60698

Related in this roundup: [CVE-2026-60672](#cve-2026-60672), [CVE-2026-60696](#cve-2026-60696).
