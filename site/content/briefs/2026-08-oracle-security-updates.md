---
title: Oracle Security Updates - August 2026
slug: 2026-08-oracle-security-updates
description: Roundup of Oracle security advisories published in August 2026.
date: "2026-08-18T22:56:20Z"
lastmod: "2026-08-18T22:57:14Z"
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
    product: WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0)
    cvss: 9.9
  - id: CVE-2026-60720
    product: Oracle Identity Manager (12.2.1.4.0, 14.1.2.1.0)
    cvss: 9.9
  - id: CVE-2026-60727
    cvss: 9.8
  - id: CVE-2026-60821
    cvss: 9.8
  - id: CVE-2026-60861
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-60921
updates:
  - at: "2026-08-18T22:56:31Z"
    level: L2
    summary: added CVE-2026-60702, CVE-2026-60720
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-60702
      - https://nvd.nist.gov/vuln/detail/CVE-2026-60720
  - at: "2026-08-18T22:57:02Z"
    level: L2
    summary: added CVE-2026-60727, CVE-2026-60821, CVE-2026-60861
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-60858
      - https://nvd.nist.gov/vuln/detail/CVE-2026-60905
      - https://nvd.nist.gov/vuln/detail/CVE-2026-60921
---

This roundup covers 18 Oracle security vulnerabilities. CVSS base scores range from 9.1 to 9.9. None are reported as actively exploited at the time of release. The issues affect Hospitality Simphony, Hyperion Calculation Manager, Identity Manager, Oracle E-Business Suite, Oracle Identity Manager, Oracle Web Services Manager, PeopleSoft Enterprise PeopleTools, Siebel CRM, WebCenter Content, WebCenter Enterprise Capture, WebCenter Portal, WebLogic Server.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-60591](#cve-2026-60591) | Hospitality Simphony (19.8-19.8.5, 19.9-19.9.3, 19.10-19.10.1) | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60591) (authoritative) |
| [CVE-2026-60672](#cve-2026-60672) | WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60672) (authoritative) |
| [CVE-2026-60696](#cve-2026-60696) | WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60696) (authoritative) |
| [CVE-2026-60698](#cve-2026-60698) | WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60698) (authoritative) |
| [CVE-2026-60702](#cve-2026-60702) | WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0) | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60702) (authoritative) |
| [CVE-2026-60720](#cve-2026-60720) | Oracle Identity Manager (12.2.1.4.0, 14.1.2.1.0) | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60720) (authoritative) |
| [CVE-2026-60721](#cve-2026-60721) | Oracle Identity Manager (12.2.1.4.0, 14.1.2.1.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60721) (authoritative) |
| [CVE-2026-60727](#cve-2026-60727) | Identity Manager (12.2.1.4.0, 14.1.2.1.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60727) (authoritative) |
| [CVE-2026-60728](#cve-2026-60728) | WebCenter Portal |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60728) (authoritative) |
| [CVE-2026-60730](#cve-2026-60730) | n/a |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60730) (authoritative) |
| [CVE-2026-60737](#cve-2026-60737) | Oracle Web Services Manager (12.2.1.4.0, 14.1.2.0.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60737) (authoritative) |
| [CVE-2026-60754](#cve-2026-60754) | Siebel CRM (17.0-26.6) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60754) (authoritative) |
| [CVE-2026-60782](#cve-2026-60782) | Oracle E-Business Suite (12.2.3-12.2.15) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60782) (authoritative) |
| [CVE-2026-60821](#cve-2026-60821) | PeopleSoft Enterprise PeopleTools (8.61-8.63) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60821) (authoritative) |
| [CVE-2026-60858](#cve-2026-60858) | Hyperion Calculation Manager (11.2.25.0.000) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60858) (authoritative) |
| [CVE-2026-60861](#cve-2026-60861) | n/a | Critical | 9.6 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60861) (authoritative) |
| [CVE-2026-60905](#cve-2026-60905) | WebCenter Content (12.2.1.4.0, 14.1.2.0.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60905) (authoritative) |
| [CVE-2026-60916](#cve-2026-60916) | WebCenter Enterprise Capture (12.2.1.4.0, 14.1.2.0.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60916) (authoritative) |


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
















Related in this roundup: [CVE-2026-60696](#cve-2026-60696), [CVE-2026-60698](#cve-2026-60698), [CVE-2026-60702](#cve-2026-60702).

## CVE-2026-60696

Oracle WebLogic Server contains a critical vulnerability in its Core component that allows unauthenticated, network-adjacent attackers to achieve full system takeover via T3 or IIOP protocols. The flaw is easily exploitable, requiring no user interaction or authentication, and impacts confidentiality, integrity, and availability.

Affected products:
- WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60696
















Related in this roundup: [CVE-2026-60672](#cve-2026-60672), [CVE-2026-60698](#cve-2026-60698), [CVE-2026-60702](#cve-2026-60702).

## CVE-2026-60698

CVE-2026-60698 is a critical vulnerability affecting the Core component of Oracle WebLogic Server. An unauthenticated attacker can exploit this via the IIOP protocol over the network to achieve full system takeover. The vulnerability carries a CVSS 3.1 score of 9.8 and impacts the confidentiality, integrity, and availability of the affected server.

Affected products:
- WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60698















Related in this roundup: [CVE-2026-60672](#cve-2026-60672), [CVE-2026-60696](#cve-2026-60696), [CVE-2026-60702](#cve-2026-60702).

## CVE-2026-60702

CVE-2026-60702 is a critical vulnerability in Oracle WebLogic Server (Core component) that allows a low-privileged attacker with network access via T3 or IIOP protocols to perform a full takeover of the server. The vulnerability has a CVSS base score of 9.9 and involves a scope change, potentially impacting other integrated products in the Fusion Middleware environment.

Affected products:
- WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60702














Related in this roundup: [CVE-2026-60672](#cve-2026-60672), [CVE-2026-60696](#cve-2026-60696), [CVE-2026-60698](#cve-2026-60698).

## CVE-2026-60720

CVE-2026-60720 is a critical vulnerability in the OIM Legacy UI component of Oracle Identity Manager versions 12.2.1.4.0 and 14.1.2.1.0. The flaw allows a low-privileged attacker with network access via HTTP to achieve full compromise of the application. Due to a scope change, this vulnerability can also impact additional products, warranting a CVSS 3.1 base score of 9.9.

Affected products:
- Oracle Identity Manager (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60720












Related in this roundup: [CVE-2026-60721](#cve-2026-60721).

## CVE-2026-60721

CVE-2026-60721 is a critical vulnerability in the OIM Legacy UI component of Oracle Identity Manager. The flaw allows an unauthenticated attacker with network access via HTTP to perform a full takeover of the application. It is classified as easily exploitable and carries a CVSS 3.1 base score of 9.8, indicating significant impact on confidentiality, integrity, and availability.

Affected products:
- Oracle Identity Manager (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60721












Related in this roundup: [CVE-2026-60720](#cve-2026-60720).

## CVE-2026-60727

CVE-2026-60727 is a critical vulnerability in the OIM Legacy UI component of Oracle Identity Manager. The vulnerability is easily exploitable by an unauthenticated attacker with network access via HTTP, potentially leading to a full system takeover. It carries a CVSS base score of 9.8, indicating significant impact on confidentiality, integrity, and availability.

Affected products:
- Identity Manager (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60727

## CVE-2026-60728

Oracle WebCenter Portal, specifically the Portlet Services component in versions 12.2.1.4.0 and 14.1.2.0.0, contains an unauthenticated vulnerability exploitable via HTTP network access. Successful exploitation allows an attacker to gain unauthorized access to sensitive data and cause a complete denial-of-service by crashing the application.

Affected products:
- WebCenter Portal

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60728

## CVE-2026-60730

CVE-2026-60730 is a critical vulnerability within the Composer component of Oracle WebCenter Portal. The flaw is remotely exploitable via HTTP by low-privileged attackers, potentially leading to a complete system takeover and impacting the confidentiality, integrity, and availability of the affected environment. The vulnerability is characterized by a scope change, indicating that successful exploitation can impact associated systems beyond the target product.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60730

## CVE-2026-60737

CVE-2026-60737 is a critical vulnerability in the Oracle Web Services Manager component of Oracle Fusion Middleware. The vulnerability allows an unauthenticated, remote attacker with HTTP network access to perform unauthorized read, write, or deletion operations on critical data managed by the service. Given the high CVSS base score and lack of required authentication or user interaction, this flaw represents a significant risk for data integrity and confidentiality.

Affected products:
- Oracle Web Services Manager (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60737

## CVE-2026-60754

CVE-2026-60754 is a critical vulnerability in the Marketing component of Oracle Siebel CRM, affecting versions 17.0 through 26.6. The flaw is remotely exploitable by an unauthenticated attacker over HTTP, potentially leading to unauthorized access to sensitive data and complete denial-of-service via application crashes.

Affected products:
- Siebel CRM (17.0-26.6)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60754

## CVE-2026-60782

CVE-2026-60782 is a critical vulnerability in the Oracle Payments component of Oracle E-Business Suite (versions 12.2.3 through 12.2.15). The flaw is remotely exploitable without authentication via HTTP and allows an attacker to achieve full takeover of the Oracle Payments service, impacting confidentiality, integrity, and availability.

Affected products:
- Oracle E-Business Suite (12.2.3-12.2.15)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60782

## CVE-2026-60821

CVE-2026-60821 is a critical vulnerability in the Business Interlink component of Oracle PeopleSoft Enterprise PeopleTools versions 8.61 through 8.63. The vulnerability is network-exploitable via HTTP by an unauthenticated attacker, allowing for a complete takeover of the PeopleTools environment. With a CVSS base score of 9.8, it poses a high risk to confidentiality, integrity, and availability.

Affected products:
- PeopleSoft Enterprise PeopleTools (8.61-8.63)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60821

## CVE-2026-60858

CVE-2026-60858 is a critical vulnerability in Oracle Hyperion Calculation Manager, version 11.2.25.0.000. The vulnerability allows an unauthenticated, network-adjacent attacker to achieve full system takeover via unauthenticated HTTP requests, resulting in total loss of confidentiality, integrity, and availability.

Affected products:
- Hyperion Calculation Manager (11.2.25.0.000)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60858

## CVE-2026-60861

CVE-2026-60861 is a critical vulnerability in the Messaging Enabler component of Oracle Fusion Middleware's Service Delivery Platform. An attacker with low privileges and network access via Oracle Net can exploit this vulnerability to achieve unauthorized access to, creation of, deletion of, or modification of critical data. Due to a change in scope, a successful exploit can impact additional products beyond the Service Delivery Platform itself.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60861

## CVE-2026-60905

CVE-2026-60905 is a high-severity vulnerability in the Oracle WebCenter Content component of Oracle Fusion Middleware. The flaw allows an unauthenticated, network-adjacent attacker to compromise the system via HTTP, provided they can induce human interaction. Successful exploitation permits unauthorized access, modification, or deletion of critical data, as well as the ability to cause a partial denial of service. The vulnerability involves a scope change, meaning impacts may extend to other products within the environment.

Affected products:
- WebCenter Content (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60905

## CVE-2026-60916

CVE-2026-60916 is a critical vulnerability in the Oracle WebCenter Enterprise Capture component of Oracle Fusion Middleware. The vulnerability is remotely exploitable without authentication via HTTP, allowing an attacker to impact confidentiality, integrity, and availability. Successful exploitation can lead to unauthorized access, modification, or deletion of critical data, as well as a partial denial-of-service, with potential for scope change affecting additional products.

Affected products:
- WebCenter Enterprise Capture (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60916
