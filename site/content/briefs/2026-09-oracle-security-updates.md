---
title: Oracle Security Updates - September 2026
slug: 2026-09-oracle-security-updates
description: Roundup of Oracle security advisories published in September 2026.
date: "2026-09-15T21:42:32Z"
lastmod: "2026-09-15T21:43:19Z"
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
    product: Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0)
    cvss: 9.9
  - id: CVE-2026-73940
    cvss: 9.8
  - id: CVE-2026-73944
    cvss: 9.1
  - id: CVE-2026-73945
    cvss: 9.9
  - id: CVE-2026-73946
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73947
updates:
  - at: "2026-09-15T21:42:53Z"
    level: L2
    summary: added CVE-2026-71133, CVE-2026-71163
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-71133
      - https://nvd.nist.gov/vuln/detail/CVE-2026-71163
  - at: "2026-09-15T21:43:02Z"
    level: L2
    summary: added CVE-2026-73940, CVE-2026-73944
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-73944
      - https://nvd.nist.gov/vuln/detail/CVE-2026-73946
  - at: "2026-09-15T21:43:19Z"
    level: L2
    summary: added CVE-2026-73945 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-73947
---

This roundup covers 10 Oracle security vulnerabilities. CVSS base scores range from 9.1 to 10.0. None are reported as actively exploited at the time of release. The issues affect Identity Manager, Oracle Access Manager, WebLogic Server.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-70748](#cve-2026-70748) | WebLogic Server | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70748) (authoritative) |
| [CVE-2026-70756](#cve-2026-70756) | WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70756) (authoritative) |
| [CVE-2026-70757](#cve-2026-70757) | WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70757) (authoritative) |
| [CVE-2026-70913](#cve-2026-70913) | Identity Manager (12.2.1.4.0, 14.1.2.1.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70913) (authoritative) |
| [CVE-2026-71133](#cve-2026-71133) | Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0) | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-71133) (authoritative) |
| [CVE-2026-71163](#cve-2026-71163) | Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0) | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-71163) (authoritative) |
| [CVE-2026-73940](#cve-2026-73940) | Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-73940) (authoritative) |
| [CVE-2026-73944](#cve-2026-73944) | Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0) | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-73944) (authoritative) |
| [CVE-2026-73945](#cve-2026-73945) | n/a |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-73945) (authoritative) |
| [CVE-2026-73946](#cve-2026-73946) | Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-73946) (authoritative) |


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





Related in this roundup: [CVE-2026-71163](#cve-2026-71163), [CVE-2026-73940](#cve-2026-73940), [CVE-2026-73944](#cve-2026-73944), [CVE-2026-73946](#cve-2026-73946).

## CVE-2026-71163

CVE-2026-71163 is a critical vulnerability affecting the Authentication Engine component of Oracle Access Manager in Oracle Fusion Middleware versions 12.2.1.4.0 and 14.1.2.1.0. A low-privileged attacker with network access via HTTP can exploit this flaw to perform unauthorized data modification, deletion, and access, as well as trigger a partial denial of service. The vulnerability supports scope change (S:C), significantly impacting the security posture of the affected environment.

Affected products:
- Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-71163





Related in this roundup: [CVE-2026-71133](#cve-2026-71133), [CVE-2026-73940](#cve-2026-73940), [CVE-2026-73944](#cve-2026-73944), [CVE-2026-73946](#cve-2026-73946).

## CVE-2026-73940

CVE-2026-73940 is a critical vulnerability in the Authentication Engine component of Oracle Access Manager, part of Oracle Fusion Middleware. The flaw allows an unauthenticated attacker to gain unauthorized control over the system via T3 or IIOP network protocols. With a CVSS base score of 9.8, this vulnerability poses a severe risk, as successful exploitation results in full compromise of the application's confidentiality, integrity, and availability.

Affected products:
- Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-73940




Related in this roundup: [CVE-2026-71133](#cve-2026-71133), [CVE-2026-71163](#cve-2026-71163), [CVE-2026-73944](#cve-2026-73944), [CVE-2026-73946](#cve-2026-73946).

## CVE-2026-73944

CVE-2026-73944 is a critical vulnerability in the Authentication Engine component of Oracle Access Manager versions 12.2.1.4.0 and 14.1.2.1.0. The vulnerability allows an unauthenticated, remote attacker to gain unauthorized access to or modify critical data within the Oracle Access Manager environment via HTTP requests. This issue carries a CVSS 3.1 base score of 9.1 and represents a significant risk to data confidentiality and integrity.

Affected products:
- Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-73944



Related in this roundup: [CVE-2026-71133](#cve-2026-71133), [CVE-2026-71163](#cve-2026-71163), [CVE-2026-73940](#cve-2026-73940), [CVE-2026-73946](#cve-2026-73946).

## CVE-2026-73945

CVE-2026-73945 is a critical vulnerability in the Authentication Engine component of Oracle Access Manager within Oracle Fusion Middleware. A low-privileged attacker with network access can exploit this via HTTP to achieve a full takeover of the Oracle Access Manager instance, potentially affecting other products due to a scope change. The vulnerability carries a CVSS base score of 9.9 and impacts confidentiality, integrity, and availability.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-73945

## CVE-2026-73946

CVE-2026-73946 is a high-severity vulnerability in the Oracle Access Manager component of Oracle Fusion Middleware. An attacker with high privileges can exploit this vulnerability over HTTP to achieve a full takeover of the Oracle Access Manager service, with potential for scope change impacting additional connected products. The vulnerability has a CVSS 3.1 base score of 9.1.

Affected products:
- Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-73946

Related in this roundup: [CVE-2026-71133](#cve-2026-71133), [CVE-2026-71163](#cve-2026-71163), [CVE-2026-73940](#cve-2026-73940), [CVE-2026-73944](#cve-2026-73944).
