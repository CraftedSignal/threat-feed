---
title: Oracle Security Updates - September 2026
slug: 2026-09-oracle-security-updates
description: Roundup of Oracle security advisories published in September 2026.
date: "2026-09-15T21:42:32Z"
lastmod: "2026-09-15T21:42:56Z"
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
  - id: CVE-2026-70748
    product: WebLogic Server
    cvss: 9.8
  - id: CVE-2026-70756
    product: WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0)
    cvss: 9.8
  - id: CVE-2026-70757
    product: WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0)
    cvss: 9.8
  - id: CVE-2026-70913
    product: Identity Manager (12.2.1.4.0, 14.1.2.1.0)
    cvss: 9.8
  - id: CVE-2026-71133
    product: Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0)
    cvss: 10
  - id: CVE-2026-71163
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71163
updates:
  - at: "2026-09-15T21:42:35Z"
    level: L2
    summary: added CVE-2026-70756 +4
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-70756
      - https://nvd.nist.gov/vuln/detail/CVE-2026-70757
      - https://nvd.nist.gov/vuln/detail/CVE-2026-70913
      - https://nvd.nist.gov/vuln/detail/CVE-2026-71133
      - https://nvd.nist.gov/vuln/detail/CVE-2026-71163
---

This roundup covers 5 Oracle security vulnerabilities. CVSS base scores range from 9.8 to 10.0. None are reported as actively exploited at the time of release. The issues affect Identity Manager, Oracle Access Manager, WebLogic Server.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-70748](#cve-2026-70748) | WebLogic Server | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70748) (authoritative) |
| [CVE-2026-70756](#cve-2026-70756) | WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70756) (authoritative) |
| [CVE-2026-70757](#cve-2026-70757) | WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70757) (authoritative) |
| [CVE-2026-70913](#cve-2026-70913) | Identity Manager (12.2.1.4.0, 14.1.2.1.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70913) (authoritative) |
| [CVE-2026-71133](#cve-2026-71133) | Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0) | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-71133) (authoritative) |


## CVE-2026-70748

Oracle WebLogic Server, specifically within the Core component, is vulnerable to an unauthenticated remote code execution exploit via T3 or IIOP protocols. Attackers can leverage this vulnerability to gain complete control over the affected server. The vulnerability is network-exploitable with low attack complexity, carrying a CVSS base score of 9.8.

Affected products:
- WebLogic Server

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-70748




Related in this roundup: [CVE-2026-70756](#cve-2026-70756), [CVE-2026-70757](#cve-2026-70757).

## CVE-2026-70756

CVE-2026-70756 is a critical vulnerability in the Core component of Oracle WebLogic Server. It allows an unauthenticated attacker with network access to exploit the T3 or IIOP protocols to achieve a full takeover of the server. With a CVSS score of 9.8, this flaw impacts confidentiality, integrity, and availability, and it is considered easily exploitable without user interaction.

Affected products:
- WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-70756




Related in this roundup: [CVE-2026-70748](#cve-2026-70748), [CVE-2026-70757](#cve-2026-70757).

## CVE-2026-70757

CVE-2026-70757 is a critical vulnerability in Oracle WebLogic Server that allows an unauthenticated attacker to take control of the server over the network via the T3 or IIOP protocols. The flaw is easily exploitable and carries a CVSS 3.1 base score of 9.8, indicating severe impact on confidentiality, integrity, and availability.

Affected products:
- WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-70757



Related in this roundup: [CVE-2026-70748](#cve-2026-70748), [CVE-2026-70756](#cve-2026-70756).

## CVE-2026-70913

CVE-2026-70913 is a critical vulnerability in the Core component of Oracle Identity Manager within Oracle Fusion Middleware. The flaw allows an unauthenticated attacker with network access via HTTP to perform a full system takeover. With a CVSS base score of 9.8, this vulnerability poses a severe risk to confidentiality, integrity, and availability.

Affected products:
- Identity Manager (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-70913

## CVE-2026-71133

CVE-2026-71133 is a critical vulnerability in the Oracle Access Manager component of Oracle Fusion Middleware. An unauthenticated attacker with network access can exploit this flaw via HTTP to achieve full takeover of the application. The vulnerability carries a CVSS 3.1 base score of 10.0 and allows for a scope change, potentially impacting other integrated products.

Affected products:
- Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-71133
