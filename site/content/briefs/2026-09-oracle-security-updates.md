---
title: Oracle Security Updates - September 2026
slug: 2026-09-oracle-security-updates
description: Roundup of Oracle security advisories published in September 2026.
date: "2026-09-15T21:42:32Z"
lastmod: "2026-09-15T21:42:38Z"
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
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-70757
updates:
  - at: "2026-09-15T21:42:32Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-70748
  - at: "2026-09-15T21:42:35Z"
    level: L2
    summary: added CVE-2026-70756, CVE-2026-70757
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-70756
      - https://nvd.nist.gov/vuln/detail/CVE-2026-70757
---

This roundup covers 2 Oracle security vulnerabilities. All have a CVSS base score of 9.8. None are reported as actively exploited at the time of release. The issues affect WebLogic Server.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-70748](#cve-2026-70748) | WebLogic Server | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70748) (authoritative) |
| [CVE-2026-70756](#cve-2026-70756) | WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70756) (authoritative) |


## CVE-2026-70748

Oracle WebLogic Server, specifically within the Core component, is vulnerable to an unauthenticated remote code execution exploit via T3 or IIOP protocols. Attackers can leverage this vulnerability to gain complete control over the affected server. The vulnerability is network-exploitable with low attack complexity, carrying a CVSS base score of 9.8.

Affected products:
- WebLogic Server

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-70748

Related in this roundup: [CVE-2026-70756](#cve-2026-70756).

## CVE-2026-70756

CVE-2026-70756 is a critical vulnerability in the Core component of Oracle WebLogic Server. It allows an unauthenticated attacker with network access to exploit the T3 or IIOP protocols to achieve a full takeover of the server. With a CVSS score of 9.8, this flaw impacts confidentiality, integrity, and availability, and it is considered easily exploitable without user interaction.

Affected products:
- WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-70756

Related in this roundup: [CVE-2026-70748](#cve-2026-70748).
