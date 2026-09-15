---
title: Oracle Security Updates - September 2026
slug: 2026-09-oracle-security-updates
description: Roundup of Oracle security advisories published in September 2026.
date: "2026-09-15T21:42:32Z"
lastmod: "2026-09-15T21:46:38Z"
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
  - id: CVE-2026-73947
    cvss: 9.8
  - id: CVE-2026-73948
    cvss: 9.9
  - id: CVE-2026-73950
    cvss: 9.8
  - id: CVE-2026-73952
    cvss: 9.1
  - id: CVE-2026-73953
    product: WebCenter Portal (12.2.1.4.0, 14.1.2.0.0)
    cvss: 9.8
  - id: CVE-2026-73956
    cvss: 9.8
  - id: CVE-2026-73957
    cvss: 9.3
  - id: CVE-2026-73961
    product: JDeveloper (12.2.1.4.0, 14.1.2.0.0)
    cvss: 9.8
  - id: CVE-2026-73962
    cvss: 9.6
  - id: CVE-2026-73963
    cvss: 9.8
  - id: CVE-2026-82994
    cvss: 9.8
  - id: CVE-2026-82995
    cvss: 9.8
  - id: CVE-2026-82997
    cvss: 9.9
  - id: CVE-2026-82998
    cvss: 9.9
  - id: CVE-2026-82999
    product: Service Delivery Platform (12.2.1.4.0, 14.1.2.0.0)
    cvss: 9.9
  - id: CVE-2026-83001
    cvss: 9.1
  - id: CVE-2026-83006
    cvss: 9.1
  - id: CVE-2026-83020
    cvss: 10
  - id: CVE-2026-83021
    cvss: 10
  - id: CVE-2026-83027
    cvss: 9.3
  - id: CVE-2026-83029
    product: Managed File Transfer (12.2.1.4.0, 14.1.2.0.0)
    cvss: 9.6
  - id: CVE-2026-83031
    cvss: 9.9
  - id: CVE-2026-83036
    product: WebCenter Sites (12.2.1.4.0, 14.1.2.0.0)
    cvss: 9.8
  - id: CVE-2026-83039
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-83057
updates:
  - at: "2026-09-15T21:46:07Z"
    level: L2
    summary: added CVE-2026-83021, CVE-2026-83036
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-83031
      - https://nvd.nist.gov/vuln/detail/CVE-2026-83036
  - at: "2026-09-15T21:46:14Z"
    level: L2
    summary: added CVE-2026-83027 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-83037
  - at: "2026-09-15T21:46:27Z"
    level: L2
    summary: added CVE-2026-82997, CVE-2026-83039
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-83043
      - https://nvd.nist.gov/vuln/detail/CVE-2026-83057
---

This roundup covers 44 Oracle security vulnerabilities. CVSS base scores range from 9.1 to 10.0. None are reported as actively exploited at the time of release. The issues affect Fusion Middleware, Identity Manager, JDeveloper, Managed File Transfer, Oracle Access Manager, Oracle Identity Manager, Oracle Identity Manager Connector, Oracle Internet Directory, Service Delivery Platform, WebCenter Enterprise Capture, WebCenter Portal, WebCenter Sites, WebLogic Server.

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
| [CVE-2026-73945](#cve-2026-73945) | n/a | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-73945) (authoritative) |
| [CVE-2026-73946](#cve-2026-73946) | Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0) | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-73946) (authoritative) |
| [CVE-2026-73947](#cve-2026-73947) | Oracle Access Manager (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-73947) (authoritative) |
| [CVE-2026-73948](#cve-2026-73948) | WebCenter Portal (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-73948) (authoritative) |
| [CVE-2026-73950](#cve-2026-73950) | Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-73950) (authoritative) |
| [CVE-2026-73952](#cve-2026-73952) | WebCenter Portal (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-73952) (authoritative) |
| [CVE-2026-73953](#cve-2026-73953) | WebCenter Portal (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-73953) (authoritative) |
| [CVE-2026-73956](#cve-2026-73956) | WebCenter Portal (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-73956) (authoritative) |
| [CVE-2026-73957](#cve-2026-73957) | n/a | Critical | 9.3 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-73957) (authoritative) |
| [CVE-2026-73961](#cve-2026-73961) | JDeveloper (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-73961) (authoritative) |
| [CVE-2026-73962](#cve-2026-73962) | Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0) | Critical | 9.6 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-73962) (authoritative) |
| [CVE-2026-73963](#cve-2026-73963) | n/a | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-73963) (authoritative) |
| [CVE-2026-82994](#cve-2026-82994) | n/a | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-82994) (authoritative) |
| [CVE-2026-82995](#cve-2026-82995) | n/a | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-82995) (authoritative) |
| [CVE-2026-82997](#cve-2026-82997) | Service Delivery Platform (12.2.1.4.0, 14.1.2.0.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-82997) (authoritative) |
| [CVE-2026-82998](#cve-2026-82998) | Fusion Middleware (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-82998) (authoritative) |
| [CVE-2026-82999](#cve-2026-82999) | Service Delivery Platform (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-82999) (authoritative) |
| [CVE-2026-83000](#cve-2026-83000) | Service Delivery Platform (12.2.1.4.0, 14.1.2.0.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83000) (authoritative) |
| [CVE-2026-83001](#cve-2026-83001) | Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0) | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83001) (authoritative) |
| [CVE-2026-83006](#cve-2026-83006) | WebCenter Enterprise Capture (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83006) (authoritative) |
| [CVE-2026-83020](#cve-2026-83020) | Fusion Middleware (12.2.1.4.0, 14.1.2.0.0) | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83020) (authoritative) |
| [CVE-2026-83021](#cve-2026-83021) | WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0) | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83021) (authoritative) |
| [CVE-2026-83027](#cve-2026-83027) | Oracle Identity Manager Connector (12.2.1.4.0, 14.1.2.1.0) | Critical | 9.3 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83027) (authoritative) |
| [CVE-2026-83029](#cve-2026-83029) | Managed File Transfer (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.6 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83029) (authoritative) |
| [CVE-2026-83031](#cve-2026-83031) | WebCenter Sites (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83031) (authoritative) |
| [CVE-2026-83035](#cve-2026-83035) | WebCenter Sites (12.2.1.4.0, 14.1.2.0.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83035) (authoritative) |
| [CVE-2026-83036](#cve-2026-83036) | WebCenter Sites (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83036) (authoritative) |
| [CVE-2026-83037](#cve-2026-83037) | WebCenter Sites (12.2.1.4.0, 14.1.2.0.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83037) (authoritative) |
| [CVE-2026-83038](#cve-2026-83038) | WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83038) (authoritative) |
| [CVE-2026-83039](#cve-2026-83039) | WebCenter Portal (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83039) (authoritative) |
| [CVE-2026-83040](#cve-2026-83040) | n/a |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83040) (authoritative) |
| [CVE-2026-83042](#cve-2026-83042) | Oracle Identity Manager (12.2.1.4.0, 14.1.2.1.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83042) (authoritative) |
| [CVE-2026-83043](#cve-2026-83043) | n/a |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83043) (authoritative) |
| [CVE-2026-83054](#cve-2026-83054) | Oracle Internet Directory (12.2.1.4.0, 14.1.2.1.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83054) (authoritative) |
| [CVE-2026-83055](#cve-2026-83055) | n/a |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83055) (authoritative) |
| [CVE-2026-83056](#cve-2026-83056) | Oracle Internet Directory (12.2.1.4.0, 14.1.2.1.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83056) (authoritative) |


## CVE-2026-70748

Oracle WebLogic Server, specifically within the Core component, is vulnerable to an unauthenticated remote code execution exploit via T3 or IIOP protocols. Attackers can leverage this vulnerability to gain complete control over the affected server. The vulnerability is network-exploitable with low attack complexity, carrying a CVSS base score of 9.8.

Affected products:
- WebLogic Server

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-70748











































Related in this roundup: [CVE-2026-70756](#cve-2026-70756), [CVE-2026-70757](#cve-2026-70757), [CVE-2026-83021](#cve-2026-83021), [CVE-2026-83038](#cve-2026-83038).

## CVE-2026-70756

CVE-2026-70756 is a critical vulnerability in the Core component of Oracle WebLogic Server. It allows an unauthenticated attacker with network access to exploit the T3 or IIOP protocols to achieve a full takeover of the server. With a CVSS score of 9.8, this flaw impacts confidentiality, integrity, and availability, and it is considered easily exploitable without user interaction.

Affected products:
- WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-70756











































Related in this roundup: [CVE-2026-70748](#cve-2026-70748), [CVE-2026-70757](#cve-2026-70757), [CVE-2026-83021](#cve-2026-83021), [CVE-2026-83038](#cve-2026-83038).

## CVE-2026-70757

CVE-2026-70757 is a critical vulnerability in Oracle WebLogic Server that allows an unauthenticated attacker to take control of the server over the network via the T3 or IIOP protocols. The flaw is easily exploitable and carries a CVSS 3.1 base score of 9.8, indicating severe impact on confidentiality, integrity, and availability.

Affected products:
- WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-70757










































Related in this roundup: [CVE-2026-70748](#cve-2026-70748), [CVE-2026-70756](#cve-2026-70756), [CVE-2026-83021](#cve-2026-83021), [CVE-2026-83038](#cve-2026-83038).

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







































Related in this roundup: [CVE-2026-71163](#cve-2026-71163), [CVE-2026-73940](#cve-2026-73940), [CVE-2026-73944](#cve-2026-73944), [CVE-2026-73946](#cve-2026-73946), [CVE-2026-73947](#cve-2026-73947), [CVE-2026-73950](#cve-2026-73950), [CVE-2026-73962](#cve-2026-73962), [CVE-2026-83001](#cve-2026-83001).

## CVE-2026-71163

CVE-2026-71163 is a critical vulnerability affecting the Authentication Engine component of Oracle Access Manager in Oracle Fusion Middleware versions 12.2.1.4.0 and 14.1.2.1.0. A low-privileged attacker with network access via HTTP can exploit this flaw to perform unauthorized data modification, deletion, and access, as well as trigger a partial denial of service. The vulnerability supports scope change (S:C), significantly impacting the security posture of the affected environment.

Affected products:
- Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-71163







































Related in this roundup: [CVE-2026-71133](#cve-2026-71133), [CVE-2026-73940](#cve-2026-73940), [CVE-2026-73944](#cve-2026-73944), [CVE-2026-73946](#cve-2026-73946), [CVE-2026-73947](#cve-2026-73947), [CVE-2026-73950](#cve-2026-73950), [CVE-2026-73962](#cve-2026-73962), [CVE-2026-83001](#cve-2026-83001).

## CVE-2026-73940

CVE-2026-73940 is a critical vulnerability in the Authentication Engine component of Oracle Access Manager, part of Oracle Fusion Middleware. The flaw allows an unauthenticated attacker to gain unauthorized control over the system via T3 or IIOP network protocols. With a CVSS base score of 9.8, this vulnerability poses a severe risk, as successful exploitation results in full compromise of the application's confidentiality, integrity, and availability.

Affected products:
- Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-73940






































Related in this roundup: [CVE-2026-71133](#cve-2026-71133), [CVE-2026-71163](#cve-2026-71163), [CVE-2026-73944](#cve-2026-73944), [CVE-2026-73946](#cve-2026-73946), [CVE-2026-73947](#cve-2026-73947), [CVE-2026-73950](#cve-2026-73950), [CVE-2026-73962](#cve-2026-73962), [CVE-2026-83001](#cve-2026-83001).

## CVE-2026-73944

CVE-2026-73944 is a critical vulnerability in the Authentication Engine component of Oracle Access Manager versions 12.2.1.4.0 and 14.1.2.1.0. The vulnerability allows an unauthenticated, remote attacker to gain unauthorized access to or modify critical data within the Oracle Access Manager environment via HTTP requests. This issue carries a CVSS 3.1 base score of 9.1 and represents a significant risk to data confidentiality and integrity.

Affected products:
- Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-73944





































Related in this roundup: [CVE-2026-71133](#cve-2026-71133), [CVE-2026-71163](#cve-2026-71163), [CVE-2026-73940](#cve-2026-73940), [CVE-2026-73946](#cve-2026-73946), [CVE-2026-73947](#cve-2026-73947), [CVE-2026-73950](#cve-2026-73950), [CVE-2026-73962](#cve-2026-73962), [CVE-2026-83001](#cve-2026-83001).

## CVE-2026-73945

CVE-2026-73945 is a critical vulnerability in the Authentication Engine component of Oracle Access Manager within Oracle Fusion Middleware. A low-privileged attacker with network access can exploit this via HTTP to achieve a full takeover of the Oracle Access Manager instance, potentially affecting other products due to a scope change. The vulnerability carries a CVSS base score of 9.9 and impacts confidentiality, integrity, and availability.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-73945

## CVE-2026-73946

CVE-2026-73946 is a high-severity vulnerability in the Oracle Access Manager component of Oracle Fusion Middleware. An attacker with high privileges can exploit this vulnerability over HTTP to achieve a full takeover of the Oracle Access Manager service, with potential for scope change impacting additional connected products. The vulnerability has a CVSS 3.1 base score of 9.1.

Affected products:
- Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-73946



































Related in this roundup: [CVE-2026-71133](#cve-2026-71133), [CVE-2026-71163](#cve-2026-71163), [CVE-2026-73940](#cve-2026-73940), [CVE-2026-73944](#cve-2026-73944), [CVE-2026-73947](#cve-2026-73947), [CVE-2026-73950](#cve-2026-73950), [CVE-2026-73962](#cve-2026-73962), [CVE-2026-83001](#cve-2026-83001).

## CVE-2026-73947

A critical vulnerability exists in the Authentication Engine component of Oracle Access Manager, part of Oracle Fusion Middleware. The flaw allows an unauthenticated attacker with network access via HTTP to fully compromise the target system, resulting in a complete takeover. Given the high CVSS base score of 9.8, the vulnerability is easily exploitable without user interaction.

Affected products:
- Oracle Access Manager (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-73947


































Related in this roundup: [CVE-2026-71133](#cve-2026-71133), [CVE-2026-71163](#cve-2026-71163), [CVE-2026-73940](#cve-2026-73940), [CVE-2026-73944](#cve-2026-73944), [CVE-2026-73946](#cve-2026-73946), [CVE-2026-73950](#cve-2026-73950), [CVE-2026-73962](#cve-2026-73962), [CVE-2026-83001](#cve-2026-83001).

## CVE-2026-73948

CVE-2026-73948 is a critical vulnerability in Oracle WebCenter Portal (part of Oracle Fusion Middleware) that allows a low-privileged, network-based attacker to gain full control of the application. The vulnerability features a scope change (S:C), indicating that successful exploitation can impact other connected products and infrastructure. Detection engineers should monitor for unauthorized HTTP traffic targeting the Composer component of the WebCenter Portal, as successful exploitation results in total system compromise with high confidentiality, integrity, and availability impact.

Affected products:
- WebCenter Portal (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-73948































Related in this roundup: [CVE-2026-73952](#cve-2026-73952), [CVE-2026-73953](#cve-2026-73953), [CVE-2026-73956](#cve-2026-73956), [CVE-2026-83039](#cve-2026-83039).

## CVE-2026-73950

Oracle Access Manager, a component of Oracle Fusion Middleware, contains a critical vulnerability in its Authentication Engine that allows an unauthenticated, remote attacker to gain full control of the application via HTTP. The vulnerability is highly exploitable, requiring no user interaction or elevated privileges, resulting in a CVSS score of 9.8.

Affected products:
- Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-73950
































Related in this roundup: [CVE-2026-71133](#cve-2026-71133), [CVE-2026-71163](#cve-2026-71163), [CVE-2026-73940](#cve-2026-73940), [CVE-2026-73944](#cve-2026-73944), [CVE-2026-73946](#cve-2026-73946), [CVE-2026-73947](#cve-2026-73947), [CVE-2026-73962](#cve-2026-73962), [CVE-2026-83001](#cve-2026-83001).

## CVE-2026-73952

CVE-2026-73952 is a critical vulnerability in the Portlet Services component of Oracle WebCenter Portal. The flaw allows an unauthenticated attacker with network access to leverage HTTP requests to achieve unauthorized creation, deletion, or modification of critical data within the application. With a CVSS base score of 9.1, it represents a significant risk to data confidentiality and integrity, necessitating immediate patching of affected 12.2.1.4.0 and 14.1.2.0.0 versions.

Affected products:
- WebCenter Portal (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-73952































Related in this roundup: [CVE-2026-73948](#cve-2026-73948), [CVE-2026-73953](#cve-2026-73953), [CVE-2026-73956](#cve-2026-73956), [CVE-2026-83039](#cve-2026-83039).

## CVE-2026-73953

CVE-2026-73953 is a critical vulnerability in the Portlet Services component of Oracle WebCenter Portal. The flaw is remotely exploitable without authentication, allowing an attacker with network access to achieve full system takeover via HTTP requests. With a CVSS base score of 9.8, it represents a high risk for complete loss of confidentiality, integrity, and availability of the affected portal instance.

Affected products:
- WebCenter Portal (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-73953






























Related in this roundup: [CVE-2026-73948](#cve-2026-73948), [CVE-2026-73952](#cve-2026-73952), [CVE-2026-73956](#cve-2026-73956), [CVE-2026-83039](#cve-2026-83039).

## CVE-2026-73956

CVE-2026-73956 is a critical vulnerability in the Composer component of Oracle WebCenter Portal within Oracle Fusion Middleware. The vulnerability is network-exploitable via HTTP by an unauthenticated attacker, potentially leading to a full takeover of the affected product. With a CVSS 3.1 base score of 9.8, this flaw impacts confidentiality, integrity, and availability.

Affected products:
- WebCenter Portal (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-73956





























Related in this roundup: [CVE-2026-73948](#cve-2026-73948), [CVE-2026-73952](#cve-2026-73952), [CVE-2026-73953](#cve-2026-73953), [CVE-2026-83039](#cve-2026-83039).

## CVE-2026-73957

CVE-2026-73957 is a critical vulnerability in the Portlet Services component of Oracle WebCenter Portal. It allows an unauthenticated, network-adjacent attacker to perform unauthorized data manipulation or access through a specifically crafted HTTP request that requires user interaction. The vulnerability has a scope change impact, potentially affecting other integrated products.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-73957

## CVE-2026-73961

CVE-2026-73961 is a critical vulnerability in the ADF Faces component of Oracle JDeveloper. The flaw allows an unauthenticated remote attacker with network access to achieve a complete takeover of the application via HTTP. Given the CVSS score of 9.8 and the lack of required authentication or user interaction, this vulnerability presents a significant risk for remote code execution.

Affected products:
- JDeveloper (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-73961

## CVE-2026-73962

CVE-2026-73962 is a critical vulnerability in the Oracle Access Manager component of Oracle Fusion Middleware. A low-privileged attacker with network access over HTTPS can exploit this flaw to bypass security controls, resulting in unauthorized access to, creation, deletion, or modification of critical data within the application. The vulnerability carries a CVSS score of 9.6 and involves a scope change, meaning it can impact other integrated products.

Affected products:
- Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-73962


























Related in this roundup: [CVE-2026-71133](#cve-2026-71133), [CVE-2026-71163](#cve-2026-71163), [CVE-2026-73940](#cve-2026-73940), [CVE-2026-73944](#cve-2026-73944), [CVE-2026-73946](#cve-2026-73946), [CVE-2026-73947](#cve-2026-73947), [CVE-2026-73950](#cve-2026-73950), [CVE-2026-83001](#cve-2026-83001).

## CVE-2026-73963

Oracle WebCenter Portal, a component of Oracle Fusion Middleware, contains a critical vulnerability in its Portlet Services that allows unauthenticated attackers to compromise the application via network access over HTTP. Successful exploitation can lead to a full takeover of the Oracle WebCenter Portal, with high impact to confidentiality, integrity, and availability.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-73963

## CVE-2026-82994

CVE-2026-82994 is a critical vulnerability in the Centralized Thirdparty Jars component of Oracle Platform Security for Java within Oracle Fusion Middleware. An unauthenticated attacker can exploit this vulnerability over a network via LDAP to achieve a full takeover of the application, impacting confidentiality, integrity, and availability with a CVSS 3.1 base score of 9.8.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-82994

## CVE-2026-82995

CVE-2026-82995 is a critical RCE vulnerability in the Centralized Thirdparty Jars component of Oracle Platform Security for Java within Oracle Fusion Middleware. The vulnerability allows an unauthenticated attacker with network access to exploit the system via SOAP requests, potentially leading to a full takeover of the affected service.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-82995

## CVE-2026-82997

CVE-2026-82997 is a critical RCE vulnerability in the Messaging Enabler component of Oracle Fusion Middleware's Service Delivery Platform. A low-privileged attacker can exploit this via network access using T3 or IIOP protocols to achieve full system takeover. The vulnerability allows for scope change, potentially impacting other products integrated with the affected platform.

Affected products:
- Service Delivery Platform (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-82997




















Related in this roundup: [CVE-2026-82999](#cve-2026-82999), [CVE-2026-83000](#cve-2026-83000).

## CVE-2026-82998

CVE-2026-82998 is a critical RCE vulnerability in the Messaging Enabler component of Oracle Fusion Middleware's Service Delivery Platform. An attacker with low privileges can exploit the vulnerability via network protocols T3 or IIOP to achieve a full takeover of the platform. Due to the scope change, successful exploitation may also impact additional products within the environment.

Affected products:
- Fusion Middleware (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-82998
















Related in this roundup: [CVE-2026-83020](#cve-2026-83020).

## CVE-2026-82999

CVE-2026-82999 is a critical vulnerability in the Messaging Enabler component of Oracle Fusion Middleware's Service Delivery Platform. A low-privileged attacker with network access can exploit this vulnerability via HTTP to achieve full takeover of the platform. The vulnerability is characterized by a scope change, allowing the compromise to impact additional products, and carries a CVSS base score of 9.9.

Affected products:
- Service Delivery Platform (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-82999




















Related in this roundup: [CVE-2026-82997](#cve-2026-82997), [CVE-2026-83000](#cve-2026-83000).

## CVE-2026-83000

CVE-2026-83000 is a critical vulnerability in the Messaging Enabler component of Oracle Fusion Middleware Service Delivery Platform. An unauthenticated attacker with network access can exploit this via HTTP to achieve full compromise of the platform. The vulnerability carries a CVSS base score of 9.8, indicating significant risks to confidentiality, integrity, and availability.

Affected products:
- Service Delivery Platform (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83000



















Related in this roundup: [CVE-2026-82997](#cve-2026-82997), [CVE-2026-82999](#cve-2026-82999).

## CVE-2026-83001

CVE-2026-83001 is a critical vulnerability in the Authentication Engine component of Oracle Access Manager within Oracle Fusion Middleware. The vulnerability is network-exploitable via HTTP and allows a high-privileged attacker to achieve a complete takeover of the Oracle Access Manager product. The exploit carries a scope change, potentially impacting additional products beyond the primary target, with significant implications for confidentiality, integrity, and availability.

Affected products:
- Oracle Access Manager (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83001


















Related in this roundup: [CVE-2026-71133](#cve-2026-71133), [CVE-2026-71163](#cve-2026-71163), [CVE-2026-73940](#cve-2026-73940), [CVE-2026-73944](#cve-2026-73944), [CVE-2026-73946](#cve-2026-73946), [CVE-2026-73947](#cve-2026-73947), [CVE-2026-73950](#cve-2026-73950), [CVE-2026-73962](#cve-2026-73962).

## CVE-2026-83006

CVE-2026-83006 is a high-severity, easily exploitable vulnerability in the Oracle WebCenter Enterprise Capture component of Oracle Fusion Middleware. A high-privileged attacker with network access can leverage HTTP requests to achieve a full takeover of the application. The vulnerability carries a CVSS 3.1 base score of 9.1 and involves a scope change, potentially impacting additional products within the environment.

Affected products:
- WebCenter Enterprise Capture (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83006

## CVE-2026-83020

CVE-2026-83020 is a critical vulnerability in the Centralized Thirdparty Jars component of Oracle Fusion Middleware's Platform Security for Java. It allows an unauthenticated, remote attacker to achieve full system takeover via HTTP. Given the scope change impact and maximum CVSS score of 10.0, this represents a severe risk that likely facilitates remote code execution or complete compromise of the underlying platform.

Affected products:
- Fusion Middleware (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83020
















Related in this roundup: [CVE-2026-82998](#cve-2026-82998).

## CVE-2026-83021

CVE-2026-83021 is a critical vulnerability in the Web Container component of Oracle WebLogic Server. The flaw allows an unauthenticated attacker with network access to achieve complete compromise (takeover) of the server via HTTP. Due to the scope change impact, the vulnerability can affect additional products in the environment, resulting in high confidentiality, integrity, and availability impacts.

Affected products:
- WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83021















Related in this roundup: [CVE-2026-70748](#cve-2026-70748), [CVE-2026-70756](#cve-2026-70756), [CVE-2026-70757](#cve-2026-70757), [CVE-2026-83038](#cve-2026-83038).

## CVE-2026-83027

CVE-2026-83027 is a critical vulnerability in the Oracle Identity Manager Connector component of Oracle Fusion Middleware. The vulnerability allows an unauthenticated, network-adjacent attacker to perform unauthorized creation, deletion, or modification of critical data, as well as unauthorized access to information within the connector, due to an insecure design or implementation in the core component. The impact is elevated due to a scope change, potentially affecting broader integrated systems.

Affected products:
- Oracle Identity Manager Connector (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83027

## CVE-2026-83029

CVE-2026-83029 is a vulnerability in the Oracle Managed File Transfer component of Oracle Fusion Middleware. The vulnerability is network-exploitable over HTTP by low-privileged attackers. Successful exploitation allows for unauthorized modification, deletion, or access to critical data within the Managed File Transfer system, with potential for scope change impacting additional associated products.

Affected products:
- Managed File Transfer (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83029

## CVE-2026-83031

CVE-2026-83031 is a critical vulnerability affecting Oracle WebCenter Sites versions 12.2.1.4.0 and 14.1.2.0.0. The vulnerability is network-exploitable over HTTP by low-privileged attackers and can lead to a full takeover of the application. Due to a scope change, successful exploitation may also impact additional products, resulting in complete compromise of confidentiality, integrity, and availability.

Affected products:
- WebCenter Sites (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83031











Related in this roundup: [CVE-2026-83035](#cve-2026-83035), [CVE-2026-83036](#cve-2026-83036), [CVE-2026-83037](#cve-2026-83037).

## CVE-2026-83035

A critical vulnerability exists in Oracle WebCenter Sites, part of the Oracle Fusion Middleware stack. The flaw allows an unauthenticated attacker with network access to achieve a full takeover of the application via HTTP. Given the CVSS score of 9.8 and the lack of authentication required, this vulnerability represents a high risk of complete system compromise.

Affected products:
- WebCenter Sites (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83035











Related in this roundup: [CVE-2026-83031](#cve-2026-83031), [CVE-2026-83036](#cve-2026-83036), [CVE-2026-83037](#cve-2026-83037).

## CVE-2026-83036

CVE-2026-83036 is a critical, easily exploitable vulnerability in Oracle WebCenter Sites (part of Oracle Fusion Middleware). The flaw allows an unauthenticated remote attacker with network access via HTTP to fully compromise the target application, leading to a complete takeover. Given the CVSS score of 9.8, this represents a high-risk vector requiring immediate patching.

Affected products:
- WebCenter Sites (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83036










Related in this roundup: [CVE-2026-83031](#cve-2026-83031), [CVE-2026-83035](#cve-2026-83035), [CVE-2026-83037](#cve-2026-83037).

## CVE-2026-83037

Oracle WebCenter Sites versions 12.2.1.4.0 and 14.1.2.0.0 are vulnerable to an unauthenticated, network-exploitable issue that allows a complete takeover of the application. The vulnerability carries a CVSS base score of 9.8, indicating critical impact on confidentiality, integrity, and availability, and can be exploited via HTTP without user interaction.

Affected products:
- WebCenter Sites (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83037









Related in this roundup: [CVE-2026-83031](#cve-2026-83031), [CVE-2026-83035](#cve-2026-83035), [CVE-2026-83036](#cve-2026-83036).

## CVE-2026-83038

Oracle WebLogic Server, specifically the TopLink Integration component, contains a critical vulnerability (CVE-2026-83038) that allows a low-privileged attacker with network access via HTTP to compromise the server. Successful exploitation results in a full system takeover and impacts additional products due to a scope change (CVSS 9.9).

Affected products:
- WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83038








Related in this roundup: [CVE-2026-70748](#cve-2026-70748), [CVE-2026-70756](#cve-2026-70756), [CVE-2026-70757](#cve-2026-70757), [CVE-2026-83021](#cve-2026-83021).

## CVE-2026-83039

CVE-2026-83039 is a critical vulnerability within the Composer component of Oracle WebCenter Portal. The flaw is remotely exploitable over HTTP by a low-privileged attacker, potentially leading to a full system takeover. The vulnerability carries a CVSS 3.1 score of 9.9 and involves a scope change that can impact integrated products, indicating a significant risk to confidentiality, integrity, and availability.

Affected products:
- WebCenter Portal (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83039







Related in this roundup: [CVE-2026-73948](#cve-2026-73948), [CVE-2026-73952](#cve-2026-73952), [CVE-2026-73953](#cve-2026-73953), [CVE-2026-73956](#cve-2026-73956).

## CVE-2026-83040

CVE-2026-83040 is a critical vulnerability in the Portlet Services component of Oracle WebCenter Portal. It allows an unauthenticated attacker with network access to exploit the system via SOAP requests. The attack requires user interaction and can lead to a full system takeover and unauthorized access, with impacts extending to other products due to scope change.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83040

## CVE-2026-83042

CVE-2026-83042 is a critical vulnerability in the OIM Legacy UI component of Oracle Identity Manager (versions 12.2.1.4.0 and 14.1.2.1.0). The vulnerability allows an unauthenticated attacker with network access via HTTP to perform a full system takeover. The vulnerability carries a CVSS 3.1 base score of 9.8, indicating high impact on confidentiality, integrity, and availability.

Affected products:
- Oracle Identity Manager (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83042

## CVE-2026-83043

CVE-2026-83043 is a critical vulnerability in Oracle WebCenter Portal, part of the Oracle Fusion Middleware suite. It allows an unauthenticated attacker with network access to achieve a full takeover of the application via HTTP. The vulnerability requires human interaction to succeed and results in a scope change, potentially impacting additional integrated products. It is highly exploitable, carrying a CVSS 3.1 base score of 9.6.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83043

## CVE-2026-83054

Oracle Internet Directory within Oracle Fusion Middleware contains a critical vulnerability in the OID LDAP Server component. The flaw is remotely exploitable without authentication via the LDAP protocol, allowing an attacker to achieve full system takeover. The vulnerability carries a CVSS base score of 9.8, indicating severe impact on confidentiality, integrity, and availability.

Affected products:
- Oracle Internet Directory (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83054

Related in this roundup: [CVE-2026-83056](#cve-2026-83056).

## CVE-2026-83055

CVE-2026-83055 is a critical vulnerability in the Oracle Internet Directory component of Oracle Fusion Middleware. A low-privileged attacker with network access via the LDAP protocol can exploit this flaw to achieve a full takeover of the Oracle Internet Directory service. The vulnerability supports scope changes, potentially impacting other integrated products, and carries a CVSS base score of 9.9.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83055

## CVE-2026-83056

Oracle Internet Directory 12.2.1.4.0 and 14.1.2.1.0 are vulnerable to a remote, easily exploitable vulnerability in the LDAP server component. A low-privileged attacker with network access can leverage this flaw to achieve a full takeover of the directory service, resulting in a complete compromise of confidentiality, integrity, and availability with scope change impact.

Affected products:
- Oracle Internet Directory (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83056

Related in this roundup: [CVE-2026-83054](#cve-2026-83054).
