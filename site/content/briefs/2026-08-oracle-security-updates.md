---
title: Oracle Security Updates - August 2026
slug: 2026-08-oracle-security-updates
description: Roundup of Oracle security advisories published in August 2026.
date: "2026-08-18T22:56:20Z"
lastmod: "2026-08-18T22:59:43Z"
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
  - id: CVE-2026-60721
    cvss: 9.8
  - id: CVE-2026-60727
    cvss: 9.8
  - id: CVE-2026-60728
    cvss: 9.1
  - id: CVE-2026-60730
    cvss: 9.9
  - id: CVE-2026-60737
    cvss: 9.1
  - id: CVE-2026-60754
    cvss: 9.1
  - id: CVE-2026-60782
    cvss: 9.8
  - id: CVE-2026-60821
    cvss: 9.8
  - id: CVE-2026-60858
    cvss: 9.8
  - id: CVE-2026-60861
    cvss: 9.6
  - id: CVE-2026-60905
    cvss: 9.6
  - id: CVE-2026-60916
    cvss: 9.9
  - id: CVE-2026-60921
    cvss: 9.8
  - id: CVE-2026-60946
    cvss: 9.8
  - id: CVE-2026-60947
    cvss: 9.8
  - id: CVE-2026-60958
    cvss: 9.8
  - id: CVE-2026-60970
    cvss: 9.8
  - id: CVE-2026-60971
    cvss: 9.8
  - id: CVE-2026-60995
    cvss: 9.9
  - id: CVE-2026-61008
    cvss: 9.1
  - id: CVE-2026-61018
    cvss: 9.8
  - id: CVE-2026-61034
    cvss: 9.1
  - id: CVE-2026-61258
    cvss: 9.8
  - id: CVE-2026-61272
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62541
updates:
  - at: "2026-08-18T22:59:19Z"
    level: L2
    summary: added CVE-2026-60971 +4
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-61258
      - https://nvd.nist.gov/vuln/detail/CVE-2026-61317
      - https://nvd.nist.gov/vuln/detail/CVE-2026-62452
      - https://nvd.nist.gov/vuln/detail/CVE-2026-62512
      - https://nvd.nist.gov/vuln/detail/CVE-2026-62541
---

This roundup covers 47 Oracle security vulnerabilities. CVSS base scores range from 9.1 to 9.9. None are reported as actively exploited at the time of release. The issues affect Hospitality Simphony, Hyperion Calculation Manager, Hyperion Infrastructure Technology, Identity Manager, Internet Directory, JD Edwards EnterpriseOne Tools, Managed File Transfer, Oracle E-Business Suite, Oracle Hyperion Infrastructure Technology, Oracle Identity Manager, Oracle Identity Manager Connector, Oracle Internet Directory, Oracle Web Services Manager, PeopleSoft Enterprise PeopleTools, Siebel CRM, Siebel CRM Cloud Applications, WebCenter Content, WebCenter Enterprise Capture, WebCenter Portal, WebCenter Sites, WebLogic Server.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-60591](#cve-2026-60591) | Hospitality Simphony (19.8-19.8.5, 19.9-19.9.3, 19.10-19.10.1) | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60591) (authoritative) |
| [CVE-2026-60672](#cve-2026-60672) | WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60672) (authoritative) |
| [CVE-2026-60696](#cve-2026-60696) | WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60696) (authoritative) |
| [CVE-2026-60698](#cve-2026-60698) | WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60698) (authoritative) |
| [CVE-2026-60702](#cve-2026-60702) | WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0) | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60702) (authoritative) |
| [CVE-2026-60720](#cve-2026-60720) | Oracle Identity Manager (12.2.1.4.0, 14.1.2.1.0) | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60720) (authoritative) |
| [CVE-2026-60721](#cve-2026-60721) | Oracle Identity Manager (12.2.1.4.0, 14.1.2.1.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60721) (authoritative) |
| [CVE-2026-60727](#cve-2026-60727) | Identity Manager (12.2.1.4.0, 14.1.2.1.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60727) (authoritative) |
| [CVE-2026-60728](#cve-2026-60728) | WebCenter Portal | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60728) (authoritative) |
| [CVE-2026-60730](#cve-2026-60730) | n/a | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60730) (authoritative) |
| [CVE-2026-60737](#cve-2026-60737) | Oracle Web Services Manager (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60737) (authoritative) |
| [CVE-2026-60754](#cve-2026-60754) | Siebel CRM (17.0-26.6) | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60754) (authoritative) |
| [CVE-2026-60782](#cve-2026-60782) | Oracle E-Business Suite (12.2.3-12.2.15) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60782) (authoritative) |
| [CVE-2026-60821](#cve-2026-60821) | PeopleSoft Enterprise PeopleTools (8.61-8.63) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60821) (authoritative) |
| [CVE-2026-60858](#cve-2026-60858) | Hyperion Calculation Manager (11.2.25.0.000) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60858) (authoritative) |
| [CVE-2026-60861](#cve-2026-60861) | n/a | Critical | 9.6 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60861) (authoritative) |
| [CVE-2026-60905](#cve-2026-60905) | WebCenter Content (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.6 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60905) (authoritative) |
| [CVE-2026-60916](#cve-2026-60916) | WebCenter Enterprise Capture (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60916) (authoritative) |
| [CVE-2026-60921](#cve-2026-60921) | WebCenter Enterprise Capture (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60921) (authoritative) |
| [CVE-2026-60946](#cve-2026-60946) | WebCenter Enterprise Capture (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60946) (authoritative) |
| [CVE-2026-60947](#cve-2026-60947) | n/a | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60947) (authoritative) |
| [CVE-2026-60958](#cve-2026-60958) | WebCenter Enterprise Capture (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60958) (authoritative) |
| [CVE-2026-60970](#cve-2026-60970) | WebCenter Enterprise Capture (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60970) (authoritative) |
| [CVE-2026-60971](#cve-2026-60971) | WebCenter Enterprise Capture (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60971) (authoritative) |
| [CVE-2026-60977](#cve-2026-60977) | WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60977) (authoritative) |
| [CVE-2026-60990](#cve-2026-60990) | Oracle Identity Manager Connector (12.2.1.4.0, 14.1.2.1.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60990) (authoritative) |
| [CVE-2026-60995](#cve-2026-60995) | Oracle Identity Manager Connector (12.2.1.4.0, 14.1.2.1.0) | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-60995) (authoritative) |
| [CVE-2026-61001](#cve-2026-61001) | Oracle Web Services Manager (12.2.1.4.0, 14.1.2.0.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-61001) (authoritative) |
| [CVE-2026-61003](#cve-2026-61003) | Managed File Transfer (12.2.1.4.0, 14.1.2.0.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-61003) (authoritative) |
| [CVE-2026-61008](#cve-2026-61008) | WebCenter Sites (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-61008) (authoritative) |
| [CVE-2026-61018](#cve-2026-61018) | WebCenter Sites (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-61018) (authoritative) |
| [CVE-2026-61021](#cve-2026-61021) | WebCenter Sites (12.2.1.4.0, 14.1.2.0.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-61021) (authoritative) |
| [CVE-2026-61029](#cve-2026-61029) | WebCenter Sites (12.2.1.4.0, 14.1.2.0.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-61029) (authoritative) |
| [CVE-2026-61034](#cve-2026-61034) | WebCenter Sites (12.2.1.4.0, 14.1.2.0.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-61034) (authoritative) |
| [CVE-2026-61066](#cve-2026-61066) | Oracle Identity Manager (12.2.1.4.0, 14.1.2.1.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-61066) (authoritative) |
| [CVE-2026-61206](#cve-2026-61206) | Hyperion Calculation Manager (11.2.25.0.000) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-61206) (authoritative) |
| [CVE-2026-61241](#cve-2026-61241) | Internet Directory (12.2.1.4.0, 14.1.2.1.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-61241) (authoritative) |
| [CVE-2026-61248](#cve-2026-61248) | Oracle Internet Directory (12.2.1.4.0, 14.1.2.1.0) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-61248) (authoritative) |
| [CVE-2026-61258](#cve-2026-61258) | Internet Directory (12.2.1.4.0, 14.1.2.1.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-61258) (authoritative) |
| [CVE-2026-61272](#cve-2026-61272) | JD Edwards EnterpriseOne Tools (9.2.0.0-9.2.26.4) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-61272) (authoritative) |
| [CVE-2026-61317](#cve-2026-61317) | Siebel CRM Cloud Applications (22.3-26.6) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-61317) (authoritative) |
| [CVE-2026-61318](#cve-2026-61318) | Siebel CRM (22.3-26.6) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-61318) (authoritative) |
| [CVE-2026-62452](#cve-2026-62452) | Siebel CRM Cloud Applications (22.3-26.6) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-62452) (authoritative) |
| [CVE-2026-62457](#cve-2026-62457) | Hyperion Infrastructure Technology (11.2.25.0.000) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-62457) (authoritative) |
| [CVE-2026-62463](#cve-2026-62463) | Oracle Hyperion Infrastructure Technology (11.2.25.0.000) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-62463) (authoritative) |
| [CVE-2026-62512](#cve-2026-62512) | Siebel CRM Cloud Applications (22.3-26.6) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-62512) (authoritative) |
| [CVE-2026-62539](#cve-2026-62539) | Hyperion Infrastructure Technology (11.2.25.0.000) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-62539) (authoritative) |


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













































Related in this roundup: [CVE-2026-60696](#cve-2026-60696), [CVE-2026-60698](#cve-2026-60698), [CVE-2026-60702](#cve-2026-60702), [CVE-2026-60977](#cve-2026-60977).

## CVE-2026-60696

Oracle WebLogic Server contains a critical vulnerability in its Core component that allows unauthenticated, network-adjacent attackers to achieve full system takeover via T3 or IIOP protocols. The flaw is easily exploitable, requiring no user interaction or authentication, and impacts confidentiality, integrity, and availability.

Affected products:
- WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60696













































Related in this roundup: [CVE-2026-60672](#cve-2026-60672), [CVE-2026-60698](#cve-2026-60698), [CVE-2026-60702](#cve-2026-60702), [CVE-2026-60977](#cve-2026-60977).

## CVE-2026-60698

CVE-2026-60698 is a critical vulnerability affecting the Core component of Oracle WebLogic Server. An unauthenticated attacker can exploit this via the IIOP protocol over the network to achieve full system takeover. The vulnerability carries a CVSS 3.1 score of 9.8 and impacts the confidentiality, integrity, and availability of the affected server.

Affected products:
- WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60698












































Related in this roundup: [CVE-2026-60672](#cve-2026-60672), [CVE-2026-60696](#cve-2026-60696), [CVE-2026-60702](#cve-2026-60702), [CVE-2026-60977](#cve-2026-60977).

## CVE-2026-60702

CVE-2026-60702 is a critical vulnerability in Oracle WebLogic Server (Core component) that allows a low-privileged attacker with network access via T3 or IIOP protocols to perform a full takeover of the server. The vulnerability has a CVSS base score of 9.9 and involves a scope change, potentially impacting other integrated products in the Fusion Middleware environment.

Affected products:
- WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0, 15.1.1.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60702











































Related in this roundup: [CVE-2026-60672](#cve-2026-60672), [CVE-2026-60696](#cve-2026-60696), [CVE-2026-60698](#cve-2026-60698), [CVE-2026-60977](#cve-2026-60977).

## CVE-2026-60720

CVE-2026-60720 is a critical vulnerability in the OIM Legacy UI component of Oracle Identity Manager versions 12.2.1.4.0 and 14.1.2.1.0. The flaw allows a low-privileged attacker with network access via HTTP to achieve full compromise of the application. Due to a scope change, this vulnerability can also impact additional products, warranting a CVSS 3.1 base score of 9.9.

Affected products:
- Oracle Identity Manager (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60720









































Related in this roundup: [CVE-2026-60721](#cve-2026-60721), [CVE-2026-61066](#cve-2026-61066).

## CVE-2026-60721

CVE-2026-60721 is a critical vulnerability in the OIM Legacy UI component of Oracle Identity Manager. The flaw allows an unauthenticated attacker with network access via HTTP to perform a full takeover of the application. It is classified as easily exploitable and carries a CVSS 3.1 base score of 9.8, indicating significant impact on confidentiality, integrity, and availability.

Affected products:
- Oracle Identity Manager (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60721









































Related in this roundup: [CVE-2026-60720](#cve-2026-60720), [CVE-2026-61066](#cve-2026-61066).

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




















Related in this roundup: [CVE-2026-61001](#cve-2026-61001).

## CVE-2026-60754

CVE-2026-60754 is a critical vulnerability in the Marketing component of Oracle Siebel CRM, affecting versions 17.0 through 26.6. The flaw is remotely exploitable by an unauthenticated attacker over HTTP, potentially leading to unauthorized access to sensitive data and complete denial-of-service via application crashes.

Affected products:
- Siebel CRM (17.0-26.6)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60754






Related in this roundup: [CVE-2026-61318](#cve-2026-61318).

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












Related in this roundup: [CVE-2026-61206](#cve-2026-61206).

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





























Related in this roundup: [CVE-2026-60921](#cve-2026-60921), [CVE-2026-60946](#cve-2026-60946), [CVE-2026-60958](#cve-2026-60958), [CVE-2026-60970](#cve-2026-60970), [CVE-2026-60971](#cve-2026-60971).

## CVE-2026-60921

CVE-2026-60921 is a critical vulnerability in Oracle WebCenter Enterprise Capture (Client Bundle component) allowing unauthenticated attackers to achieve full system takeover via T3 or IIOP network protocols. The vulnerability carries a CVSS 3.1 base score of 9.8 and impacts confidentiality, integrity, and availability.

Affected products:
- WebCenter Enterprise Capture (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60921





























Related in this roundup: [CVE-2026-60916](#cve-2026-60916), [CVE-2026-60946](#cve-2026-60946), [CVE-2026-60958](#cve-2026-60958), [CVE-2026-60970](#cve-2026-60970), [CVE-2026-60971](#cve-2026-60971).

## CVE-2026-60946

CVE-2026-60946 is a critical vulnerability in Oracle WebCenter Enterprise Capture (part of Oracle Fusion Middleware) involving the Client Bundle component. The vulnerability allows an unauthenticated attacker to execute code remotely via RMI with network access, leading to a full takeover of the application. It is highly exploitable and impacts the confidentiality, integrity, and availability of the system.

Affected products:
- WebCenter Enterprise Capture (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60946




























Related in this roundup: [CVE-2026-60916](#cve-2026-60916), [CVE-2026-60921](#cve-2026-60921), [CVE-2026-60958](#cve-2026-60958), [CVE-2026-60970](#cve-2026-60970), [CVE-2026-60971](#cve-2026-60971).

## CVE-2026-60947

CVE-2026-60947 is a critical vulnerability in the Oracle WebCenter Enterprise Capture component of Oracle Fusion Middleware. The vulnerability allows an unauthenticated, network-adjacent attacker to achieve full system takeover via RMI requests. Detection engineers should monitor for unauthorized or unusual RMI traffic patterns directed at the WebCenter Enterprise Capture application, as successful exploitation results in complete compromise of confidentiality, integrity, and availability.

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60947

## CVE-2026-60958

CVE-2026-60958 is a critical vulnerability in the Oracle WebCenter Enterprise Capture component of Oracle Fusion Middleware. The vulnerability is remotely exploitable without authentication via HTTP and can lead to a full system takeover, indicating a high risk of remote code execution or significant privilege manipulation.

Affected products:
- WebCenter Enterprise Capture (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60958


























Related in this roundup: [CVE-2026-60916](#cve-2026-60916), [CVE-2026-60921](#cve-2026-60921), [CVE-2026-60946](#cve-2026-60946), [CVE-2026-60970](#cve-2026-60970), [CVE-2026-60971](#cve-2026-60971).

## CVE-2026-60970

CVE-2026-60970 is a critical vulnerability in the Oracle WebCenter Enterprise Capture component of Oracle Fusion Middleware. The flaw allows an unauthenticated attacker with network access via T3 or IIOP protocols to achieve full system takeover. The vulnerability carries a CVSS base score of 9.8 and impacts the confidentiality, integrity, and availability of the affected system.

Affected products:
- WebCenter Enterprise Capture (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60970

























Related in this roundup: [CVE-2026-60916](#cve-2026-60916), [CVE-2026-60921](#cve-2026-60921), [CVE-2026-60946](#cve-2026-60946), [CVE-2026-60958](#cve-2026-60958), [CVE-2026-60971](#cve-2026-60971).

## CVE-2026-60971

CVE-2026-60971 is a critical vulnerability (CVSS 9.8) affecting Oracle WebCenter Enterprise Capture within Oracle Fusion Middleware. An unauthenticated attacker with network access via T3 or IIOP protocols can exploit this flaw to fully compromise the target application. Successful exploitation leads to a complete takeover of the service, impacting confidentiality, integrity, and availability.

Affected products:
- WebCenter Enterprise Capture (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60971
























Related in this roundup: [CVE-2026-60916](#cve-2026-60916), [CVE-2026-60921](#cve-2026-60921), [CVE-2026-60946](#cve-2026-60946), [CVE-2026-60958](#cve-2026-60958), [CVE-2026-60970](#cve-2026-60970).

## CVE-2026-60977

CVE-2026-60977 is a critical remote code execution vulnerability in the WLS Core Components of Oracle WebLogic Server. The vulnerability allows unauthenticated attackers with network access to the server to gain full control via RMI, resulting in a complete takeover of the affected component. It is rated with a CVSS 3.1 base score of 9.8.

Affected products:
- WebLogic Server (12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60977























Related in this roundup: [CVE-2026-60672](#cve-2026-60672), [CVE-2026-60696](#cve-2026-60696), [CVE-2026-60698](#cve-2026-60698), [CVE-2026-60702](#cve-2026-60702).

## CVE-2026-60990

CVE-2026-60990 is a critical vulnerability in the Oracle Identity Manager Connector component of Oracle Fusion Middleware. A low-privileged attacker with network access over TLS can exploit this vulnerability to achieve full compromise (takeover) of the component. The vulnerability carries a CVSS base score of 9.9 and allows for scope change, indicating the potential to impact additional products within the environment.

Affected products:
- Oracle Identity Manager Connector (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60990





















Related in this roundup: [CVE-2026-60995](#cve-2026-60995).

## CVE-2026-60995

CVE-2026-60995 is a critical vulnerability in the Oracle Identity Manager Connector component of Oracle Fusion Middleware. A low-privileged attacker with network access via TLS can exploit this flaw to achieve full system takeover. The vulnerability allows for scope change, potentially impacting additional products in the environment, and carries a CVSS base score of 9.9.

Affected products:
- Oracle Identity Manager Connector (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-60995





















Related in this roundup: [CVE-2026-60990](#cve-2026-60990).

## CVE-2026-61001

CVE-2026-61001 is a critical vulnerability in Oracle Web Services Manager within Oracle Fusion Middleware, allowing a low-privileged attacker with network access via HTTP to compromise the service. Due to a scope change (S:C), the vulnerability can result in unauthorized creation, deletion, or modification of critical data. It carries a CVSS 3.1 base score of 9.6, indicating significant impact to confidentiality and integrity.

Affected products:
- Oracle Web Services Manager (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-61001




















Related in this roundup: [CVE-2026-60737](#cve-2026-60737).

## CVE-2026-61003

A critical vulnerability exists in the Oracle Managed File Transfer component of Oracle Fusion Middleware, allowing a low-privileged, network-adjacent attacker to achieve full takeover of the MFT Runtime Server via T3 or IIOP protocols. The flaw supports scope change, meaning exploitation can potentially lead to the compromise of additional products within the environment, warranting immediate patching.

Affected products:
- Managed File Transfer (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-61003

## CVE-2026-61008

CVE-2026-61008 is a critical vulnerability in Oracle WebCenter Sites (part of Fusion Middleware) that allows an unauthenticated, network-adjacent attacker to perform unauthorized creation, deletion, or modification of critical data. With a CVSS 3.1 score of 9.1, this flaw is highly exploitable via HTTP and impacts the confidentiality and integrity of the application data.

Affected products:
- WebCenter Sites (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-61008

















Related in this roundup: [CVE-2026-61018](#cve-2026-61018), [CVE-2026-61021](#cve-2026-61021), [CVE-2026-61029](#cve-2026-61029), [CVE-2026-61034](#cve-2026-61034).

## CVE-2026-61018

CVE-2026-61018 is a critical vulnerability affecting Oracle WebCenter Sites versions 12.2.1.4.0 and 14.1.2.0.0 within the Oracle Fusion Middleware suite. The vulnerability is easily exploitable by an unauthenticated attacker with network access via HTTP, potentially leading to a full system takeover. It carries a CVSS 3.1 base score of 9.8, indicating severe confidentiality, integrity, and availability impacts.

Affected products:
- WebCenter Sites (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-61018

















Related in this roundup: [CVE-2026-61008](#cve-2026-61008), [CVE-2026-61021](#cve-2026-61021), [CVE-2026-61029](#cve-2026-61029), [CVE-2026-61034](#cve-2026-61034).

## CVE-2026-61021

A critical vulnerability exists in Oracle WebCenter Sites within the Oracle Fusion Middleware suite, allowing low-privileged, network-adjacent attackers to achieve complete system takeover via HTTP. The vulnerability has a CVSS 3.1 base score of 9.9 and impacts confidentiality, integrity, and availability, with an associated scope change that may affect secondary products.

Affected products:
- WebCenter Sites (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-61021
















Related in this roundup: [CVE-2026-61008](#cve-2026-61008), [CVE-2026-61018](#cve-2026-61018), [CVE-2026-61029](#cve-2026-61029), [CVE-2026-61034](#cve-2026-61034).

## CVE-2026-61029

Oracle WebCenter Sites 12.2.1.4.0 and 14.1.2.0.0 are vulnerable to an unauthenticated, remote code execution or takeover attack. The vulnerability is accessible over the network via HTTP and allows for significant impact across the environment due to a change in scope, carrying a CVSS 3.1 base score of 9.0.

Affected products:
- WebCenter Sites (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-61029















Related in this roundup: [CVE-2026-61008](#cve-2026-61008), [CVE-2026-61018](#cve-2026-61018), [CVE-2026-61021](#cve-2026-61021), [CVE-2026-61034](#cve-2026-61034).

## CVE-2026-61034

CVE-2026-61034 is a critical vulnerability in Oracle WebCenter Sites within Oracle Fusion Middleware. The flaw is remotely exploitable over HTTP by a high-privileged attacker, potentially leading to a full system takeover and impacting additional products through scope change. The vulnerability carries a CVSS 3.1 base score of 9.1.

Affected products:
- WebCenter Sites (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-61034














Related in this roundup: [CVE-2026-61008](#cve-2026-61008), [CVE-2026-61018](#cve-2026-61018), [CVE-2026-61021](#cve-2026-61021), [CVE-2026-61029](#cve-2026-61029).

## CVE-2026-61066

CVE-2026-61066 is a critical vulnerability in the OIM Legacy UI component of Oracle Identity Manager. An attacker with low privileges can exploit this vulnerability via RMI over the network to achieve a full takeover of the application. The vulnerability carries a CVSS 3.1 score of 9.9 and involves a scope change, meaning it can facilitate broader compromise beyond the Oracle Identity Manager environment.

Affected products:
- Oracle Identity Manager (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-61066













Related in this roundup: [CVE-2026-60720](#cve-2026-60720), [CVE-2026-60721](#cve-2026-60721).

## CVE-2026-61206

CVE-2026-61206 is a critical vulnerability in the Security component of Oracle Hyperion Calculation Manager version 11.2.25.0.000. It allows a low-privileged, network-based attacker to execute a successful takeover of the application via HTTP. The vulnerability has a CVSS base score of 9.9 and involves a scope change, potentially impacting additional products within the environment.

Affected products:
- Hyperion Calculation Manager (11.2.25.0.000)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-61206












Related in this roundup: [CVE-2026-60858](#cve-2026-60858).

## CVE-2026-61241

CVE-2026-61241 is a critical vulnerability in the OID LDAP Server component of Oracle Internet Directory. The flaw is remotely exploitable without authentication via the LDAP protocol, allowing an attacker to achieve a complete takeover of the directory service. The vulnerability carries a CVSS base score of 10.0 and impacts the confidentiality, integrity, and availability of the system with an increased scope.

Affected products:
- Internet Directory (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-61241









Related in this roundup: [CVE-2026-61258](#cve-2026-61258).

## CVE-2026-61248

CVE-2026-61248 is a critical vulnerability in the Oracle Internet Directory component of Oracle Fusion Middleware. A low-privileged attacker with network access via the LDAP protocol can achieve a full takeover of the Oracle Internet Directory. Due to the scope change (S:C), successful exploitation impacts the confidentiality, integrity, and availability of the directory service and potentially associated systems.

Affected products:
- Oracle Internet Directory (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-61248

## CVE-2026-61258

CVE-2026-61258 is a critical vulnerability in the Oracle Internet Directory component of Oracle Fusion Middleware. An unauthenticated attacker can exploit this flaw via the LDAP protocol over the network to achieve a full takeover of the affected service. The vulnerability has a CVSS base score of 9.8, indicating high impact on confidentiality, integrity, and availability.

Affected products:
- Internet Directory (12.2.1.4.0, 14.1.2.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-61258









Related in this roundup: [CVE-2026-61241](#cve-2026-61241).

## CVE-2026-61272

CVE-2026-61272 is a critical vulnerability in the Web Runtime SEC component of Oracle JD Edwards EnterpriseOne Tools versions 9.2.0.0 through 9.2.26.4. The vulnerability allows an unauthenticated attacker with network access via HTTP to perform a full system takeover. Given the CVSS score of 9.8 and the lack of required authentication, this flaw represents a significant risk for RCE or full application compromise.

Affected products:
- JD Edwards EnterpriseOne Tools (9.2.0.0-9.2.26.4)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-61272

## CVE-2026-61317

CVE-2026-61317 is a critical vulnerability in the Oracle Siebel Cloud Manager component of Siebel CRM Cloud Applications (versions 22.3-26.6). A low-privileged attacker with network access can exploit this via HTTP to achieve full system takeover. The vulnerability carries a CVSS 3.1 base score of 9.9 and involves a scope change, allowing impacts to propagate to other products.

Affected products:
- Siebel CRM Cloud Applications (22.3-26.6)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-61317





Related in this roundup: [CVE-2026-62452](#cve-2026-62452), [CVE-2026-62512](#cve-2026-62512).

## CVE-2026-61318

CVE-2026-61318 is a critical vulnerability in Oracle Siebel CRM Cloud Applications, specifically within the Siebel Cloud Manager component. The flaw allows an unauthenticated, network-adjacent attacker to achieve full system takeover via HTTP requests. With a CVSS 3.1 base score of 9.8, this vulnerability poses a severe risk to confidentiality, integrity, and availability.

Affected products:
- Siebel CRM (22.3-26.6)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-61318






Related in this roundup: [CVE-2026-60754](#cve-2026-60754).

## CVE-2026-62452

CVE-2026-62452 is a critical, easily exploitable vulnerability in the Siebel Cloud Manager component of Oracle Siebel CRM Cloud Applications (versions 22.3-26.6). An unauthenticated attacker with network access can leverage HTTP to achieve unauthorized access to critical data, perform unauthorized modifications (update, insert, or delete) on accessible data, and trigger a partial denial of service. The vulnerability impacts the confidentiality, integrity, and availability of the application with a CVSS 3.1 base score of 9.9.

Affected products:
- Siebel CRM Cloud Applications (22.3-26.6)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-62452





Related in this roundup: [CVE-2026-61317](#cve-2026-61317), [CVE-2026-62512](#cve-2026-62512).

## CVE-2026-62457

CVE-2026-62457 is a critical vulnerability in the Common Events component of Oracle Hyperion Infrastructure Technology version 11.2.25.0.000. The flaw is remotely exploitable without authentication via HTTP, potentially allowing an attacker to achieve full system takeover by compromising confidentiality, integrity, and availability. With a CVSS base score of 9.8, it represents a high-risk entry point for unauthorized remote access.

Affected products:
- Hyperion Infrastructure Technology (11.2.25.0.000)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-62457

Related in this roundup: [CVE-2026-62539](#cve-2026-62539).

## CVE-2026-62463

Oracle Hyperion Infrastructure Technology version 11.2.25.0.000 is vulnerable to an easily exploitable flaw in the Lifecycle Management component. A low-privileged attacker with network access via HTTP can trigger a scope change to perform unauthorized data modification, deletion, or access to critical system data. The vulnerability carries a high CVSS base score of 9.6, indicating significant impact on data confidentiality and integrity.

Affected products:
- Oracle Hyperion Infrastructure Technology (11.2.25.0.000)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-62463

## CVE-2026-62512

CVE-2026-62512 is a critical vulnerability in Oracle Siebel CRM Cloud Applications, specifically within the Siebel Cloud Manager component. The vulnerability allows a low-privileged, network-adjacent attacker to achieve full system takeover via HTTP requests. Due to the high CVSS score of 9.9 and the potential for a scope change affecting downstream products, this vulnerability represents a significant risk to confidentiality, integrity, and availability.

Affected products:
- Siebel CRM Cloud Applications (22.3-26.6)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-62512


Related in this roundup: [CVE-2026-61317](#cve-2026-61317), [CVE-2026-62452](#cve-2026-62452).

## CVE-2026-62539

CVE-2026-62539 is a critical vulnerability affecting the Installation and Configuration component of Oracle Hyperion Infrastructure Technology version 11.2.25.0.000. An unauthenticated attacker can exploit this flaw over the network via HTTP to achieve full compromise of the application, resulting in impacts to confidentiality, integrity, and availability with a CVSS base score of 9.8.

Affected products:
- Hyperion Infrastructure Technology (11.2.25.0.000)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-62539

Related in this roundup: [CVE-2026-62457](#cve-2026-62457).
