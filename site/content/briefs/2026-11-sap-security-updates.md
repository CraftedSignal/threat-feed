---
brief_id: brief-2026-11-sap-security-updates
event_id: brief-2026-11-sap-security-updates
revision: 3
activity_at: "2026-11-10T02:09:13Z"
revision_history:
  - revision: 2
    at: "2026-11-10T02:06:39Z"
    checksum: sha256:9c6bd1f14c5e87506321bea074fb426bb859c360577bd4503f1163822b54e8f3
    summary: added CVE-2026-109800
    changed_fields:
      - content
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-109807
  - revision: 3
    at: "2026-11-10T02:09:13Z"
    checksum: sha256:6e70656461ce37d0d117ef7524c3809a42e74368ec6bb1996c2269d272bd85bc
    summary: added CVE-2026-109806 +2
    changed_fields:
      - content
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76970
title: SAP Security Updates - November 2026
slug: 2026-11-sap-security-updates
description: Roundup of SAP security advisories published in November 2026.
date: "2026-11-10T02:00:57Z"
lastmod: "2026-11-10T02:08:07Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
tags:
  - roundup
vendors:
  - SAP
cves:
  - id: CVE-2026-109795
    product: NetWeaver
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-109798
    product: BusinessObjects Business Intelligence Platform
    cvss: 9.1
    kev_status: "false"
  - id: CVE-2026-109803
    product: NetWeaver Knowledge Management
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-120017
    product: NetWeaver AS ABAP
    cvss: 10
    kev_status: "false"
  - id: CVE-2026-76964
    product: NetWeaver Application Server ABAP
    cvss: 10
    kev_status: "false"
  - id: CVE-2026-76965
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-89103
    product: SAP Gateway
    cvss: 10
    kev_status: "false"
  - id: CVE-2026-89119
    product: Web Dispatcher
    cvss: 9.6
    kev_status: "false"
  - id: CVE-2026-89126
    cvss: 10
    kev_status: "false"
  - id: CVE-2026-109800
    cvss: 7.7
    kev_status: "false"
  - id: CVE-2026-109794
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-109799
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-109797
    cvss: 7.1
    kev_status: "false"
  - id: CVE-2026-109804
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-109807
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-120008
    cvss: 8.2
    kev_status: "false"
  - id: CVE-2026-109793
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-109806
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-120014
    cvss: 7.6
    kev_status: "false"
  - id: CVE-2026-76970
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-120010
    kev_status: unknown
  - id: CVE-2026-120015
    kev_status: unknown
  - id: CVE-2026-76966
    kev_status: unknown
  - id: CVE-2026-120009
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76970
updates:
  - at: "2026-11-10T02:07:58Z"
    level: L2
    summary: added CVE-2026-109794 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120010
  - at: "2026-11-10T02:08:00Z"
    level: L2
    summary: added CVE-2026-109797 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120014
  - at: "2026-11-10T02:08:01Z"
    level: L2
    summary: added CVE-2026-109807 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120015
  - at: "2026-11-10T02:08:06Z"
    level: L2
    summary: added CVE-2026-109793
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76966
  - at: "2026-11-10T02:08:07Z"
    level: L2
    summary: added CVE-2026-109806 +2
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76970
---

This roundup covers 23 SAP security vulnerabilities. CVSS base scores range from 7.1 to 10.0. None are reported as actively exploited at the time of release. The issues affect ABAP Developer Tools, BusinessObjects Business Intelligence Platform, Cloud SDK for Python, HANA XSA Web Dispatcher, Host Agent, Message Server, NetWeaver, NetWeaver AS ABAP, NetWeaver Application Server, NetWeaver Application Server ABAP, NetWeaver Knowledge Management, SAP Gateway, SAP NetWeaver, Web Dispatcher, astonish.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-109795](#cve-2026-109795) | NetWeaver | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109795) (authoritative) |
| [CVE-2026-109798](#cve-2026-109798) | BusinessObjects Business Intelligence Platform | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109798) (authoritative) |
| [CVE-2026-109803](#cve-2026-109803) | NetWeaver Knowledge Management | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109803) (authoritative) |
| [CVE-2026-120017](#cve-2026-120017) | NetWeaver AS ABAP | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-120017) (authoritative) |
| [CVE-2026-76964](#cve-2026-76964) | NetWeaver Application Server ABAP | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76964) (authoritative) |
| [CVE-2026-76965](#cve-2026-76965) | NetWeaver Application Server ABAP | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76965) (authoritative) |
| [CVE-2026-89103](#cve-2026-89103) | SAP Gateway | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-89103) (authoritative) |
| [CVE-2026-89119](#cve-2026-89119) | Web Dispatcher | Critical | 9.6 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-89119) (authoritative) |
| [CVE-2026-89126](#cve-2026-89126) | Web Dispatcher | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-89126) (authoritative) |
| [CVE-2026-109793](#cve-2026-109793) | NetWeaver Application Server ABAP | High | 7.5 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109793) (authoritative) |
| [CVE-2026-109794](#cve-2026-109794) | NetWeaver Application Server ABAP | High | 7.5 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109794) (authoritative) |
| [CVE-2026-109797](#cve-2026-109797) | astonish | High | 7.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109797) (authoritative) |
| [CVE-2026-109799](#cve-2026-109799) | Cloud SDK for Python | High | 7.5 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109799) (authoritative) |
| [CVE-2026-109800](#cve-2026-109800) | Web Dispatcher | High | 7.7 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109800) (authoritative) |
| [CVE-2026-109804](#cve-2026-109804) | Message Server | High | 7.5 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109804) (authoritative) |
| [CVE-2026-109806](#cve-2026-109806) | NetWeaver |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109806) (authoritative) |
| [CVE-2026-109807](#cve-2026-109807) | NetWeaver | High | 7.5 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109807) (authoritative) |
| [CVE-2026-120008](#cve-2026-120008) | NetWeaver | High | 8.2 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-120008) (authoritative) |
| [CVE-2026-120009](#cve-2026-120009) | ABAP Developer Tools |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-120009) (authoritative) |
| [CVE-2026-120010](#cve-2026-120010) | NetWeaver Application Server |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-120010) (authoritative) |
| [CVE-2026-120014](#cve-2026-120014) | HANA XSA Web Dispatcher |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-120014) (authoritative) |
| [CVE-2026-120015](#cve-2026-120015) | Host Agent |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-120015) (authoritative) |
| [CVE-2026-76966](#cve-2026-76966) | SAP NetWeaver |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-76966) (authoritative) |


## CVE-2026-109795

SAP NetWeaver contains a critical vulnerability where remote-enabled functionality lacks proper authorization checks and input validation. A low-privileged attacker can leverage this flaw to inject and execute arbitrary code, potentially leading to full compromise of system confidentiality, integrity, and availability.

Affected products:
- NetWeaver

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-109795








Related in this roundup: [CVE-2026-109806](#cve-2026-109806), [CVE-2026-109807](#cve-2026-109807), [CVE-2026-120008](#cve-2026-120008).

## CVE-2026-109798

SAP BusinessObjects Business Intelligence Platform (Web Intelligence) fails to properly restrict external entity resolution during the processing of OLAP connection requests. This vulnerability allows an authenticated attacker to perform XML External Entity (XXE) attacks, leading to unauthorized access to sensitive files on the server and potential reach into internal systems that are otherwise restricted.

Affected products:
- BusinessObjects Business Intelligence Platform

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-109798

## CVE-2026-109803

SAP NetWeaver Knowledge Management (XML Forms) is vulnerable to a flaw where XSL transformations are not sufficiently restricted. An authenticated user can trigger an unauthorized XSL transformation, potentially resulting in remote code execution within the application context, impacting confidentiality, integrity, and availability.

Affected products:
- NetWeaver Knowledge Management

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-109803

## CVE-2026-120017

SAP NetWeaver AS ABAP and ABAP Platform contain an authentication bypass vulnerability due to insufficient verification of incoming authentication assertions. An unauthenticated attacker can submit specially crafted data to impersonate arbitrary users, including those with high-level privileges, leading to full system compromise and potential lateral movement into connected systems.

Affected products:
- NetWeaver AS ABAP
- ABAP Platform

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-120017

## CVE-2026-76964

SAP NetWeaver Application Server ABAP contains a vulnerability where insufficient validation of network input allows an unauthenticated attacker to trigger memory corruption. This flaw can lead to remote code execution and full system compromise, affecting the confidentiality, integrity, and availability of the SAP environment.

Affected products:
- NetWeaver Application Server ABAP

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76964


















Related in this roundup: [CVE-2026-76965](#cve-2026-76965), [CVE-2026-109793](#cve-2026-109793), [CVE-2026-109794](#cve-2026-109794).

## CVE-2026-76965

SAP NetWeaver Application Server ABAP and ABAP Platform contain an authorization bypass vulnerability allowing low-privileged authenticated users to execute arbitrary operating system commands. The lack of proper authorization checks for internal functionality facilitates remote code execution (RCE) with high impact on confidentiality, integrity, and availability.

Affected products:
- NetWeaver Application Server ABAP
- ABAP Platform

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76965


















Related in this roundup: [CVE-2026-76964](#cve-2026-76964), [CVE-2026-109793](#cve-2026-109793), [CVE-2026-109794](#cve-2026-109794).

## CVE-2026-89103

SAP Gateway contains a vulnerability where the default Access Control List (ACL) is configured with excessive privileges. This allows an unauthenticated, network-adjacent attacker to be miscategorized as an internal application server, potentially enabling unauthorized actions that compromise the confidentiality, integrity, and availability of the SAP environment.

Affected products:
- SAP Gateway

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-89103

## CVE-2026-89119

SAP Web Dispatcher and SAP NetWeaver Application Server ABAP are vulnerable to a Cross-Site Request Forgery (CSRF) attack due to insufficient request validation within administrative functionality. An unauthenticated attacker can deceive an authenticated administrator into executing malicious actions by clicking a crafted link, potentially resulting in full system compromise.

Affected products:
- Web Dispatcher
- NetWeaver Application Server ABAP

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-89119















Related in this roundup: [CVE-2026-89126](#cve-2026-89126), [CVE-2026-109800](#cve-2026-109800).

## CVE-2026-89126

SAP Web Dispatcher contains a vulnerability where insufficient validation of network input leads to a memory corruption condition. An unauthenticated attacker can exploit this via specially crafted network traffic to achieve remote code execution, resulting in full system compromise.

Affected products:
- Web Dispatcher

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-89126















Related in this roundup: [CVE-2026-89119](#cve-2026-89119), [CVE-2026-109800](#cve-2026-109800).

## CVE-2026-109793

SAP NetWeaver Application Server ABAP and SAP Web Dispatcher contain a vulnerability where insufficient validation of inbound header values allows an unauthenticated attacker to trigger a denial-of-service condition, impacting system availability.

Affected products:
- NetWeaver Application Server ABAP
- SAP Web Dispatcher

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-109793














Related in this roundup: [CVE-2026-76964](#cve-2026-76964), [CVE-2026-76965](#cve-2026-76965), [CVE-2026-109794](#cve-2026-109794).

## CVE-2026-109794

SAP NetWeaver Application Server ABAP, ABAP Platform, and SAP Web Dispatcher are vulnerable to a resource exhaustion flaw due to improper handling of specific requests. An unauthenticated attacker can exploit this via specially crafted requests to trigger excessive resource consumption, leading to a denial-of-service condition affecting the availability of the application.

Affected products:
- NetWeaver Application Server ABAP
- ABAP Platform
- SAP Web Dispatcher

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-109794













Related in this roundup: [CVE-2026-76964](#cve-2026-76964), [CVE-2026-76965](#cve-2026-76965), [CVE-2026-109793](#cve-2026-109793).

## CVE-2026-109797

The SAP 'astonish' platform is vulnerable to an authentication-related cross-tenant container access flaw within its legacy Incus sandbox-management API. An authenticated user can leverage improper tenant isolation to list, proxy, or delete containers belonging to other teams. The vulnerability is restricted to the legacy Incus backend and does not impact Kubernetes or OpenShell deployment environments.

Affected products:
- astonish

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-109797

## CVE-2026-109799

The SAP Cloud SDK for Python contains a vulnerability in the IASContextProvider component where cryptographic signatures of IAS JWTs in the Authorization header are not verified. This allows a remote attacker to submit a self-signed JWT, enabling identity spoofing for specific tenants or users, which subsequently propagates to downstream components including telemetry, logging, audit services, and tenant routing systems.

Affected products:
- Cloud SDK for Python

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-109799

## CVE-2026-109800

SAP Web Dispatcher is vulnerable to a memory corruption flaw due to insufficient input validation. An authenticated non-administrative user can trigger a process termination, resulting in a denial-of-service condition for the Web Dispatcher and all downstream backend systems.

Affected products:
- Web Dispatcher

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-109800










Related in this roundup: [CVE-2026-89119](#cve-2026-89119), [CVE-2026-89126](#cve-2026-89126).

## CVE-2026-109804

SAP Message Server is vulnerable to a flaw where improper handling of malformed requests allows an unauthenticated attacker to retrieve sensitive information, resulting in a high impact on confidentiality.

Affected products:
- Message Server

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-109804

## CVE-2026-109806

SAP NetWeaver Internet Graphics Service (IGS) contains an integer overflow vulnerability due to insufficient input validation. An unauthenticated remote attacker can exploit this by sending specially crafted malformed image data to trigger a crash of the worker process, resulting in a denial-of-service (DoS) condition.

Affected products:
- NetWeaver

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-109806








Related in this roundup: [CVE-2026-109795](#cve-2026-109795), [CVE-2026-109807](#cve-2026-109807), [CVE-2026-120008](#cve-2026-120008).

## CVE-2026-109807

SAP NetWeaver Internet Graphics Service (IGS) contains a vulnerability where insufficient input validation allows an unauthenticated remote attacker to trigger a crash of the worker process. The attack results in a denial-of-service condition by causing the process to read beyond its declared memory bounds, leading to repeated service termination.

Affected products:
- NetWeaver

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-109807







Related in this roundup: [CVE-2026-109795](#cve-2026-109795), [CVE-2026-109806](#cve-2026-109806), [CVE-2026-120008](#cve-2026-120008).

## CVE-2026-120008

SAP NetWeaver Internet Graphics Service (IGS) contains a vulnerability where insufficient input validation allows an unauthenticated remote attacker to trigger an out-of-bounds memory write. This can lead to memory corruption and repeated process crashes, causing a denial-of-service condition affecting system availability.

Affected products:
- NetWeaver

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-120008






Related in this roundup: [CVE-2026-109795](#cve-2026-109795), [CVE-2026-109806](#cve-2026-109806), [CVE-2026-109807](#cve-2026-109807).

## CVE-2026-120009

SAP ABAP Developer Tools (AMDP Data Preview) is vulnerable to a code injection vulnerability due to insufficient input validation and authorization checks. A high-privileged attacker can leverage this flaw to execute arbitrary code on the underlying system, leading to a full compromise of confidentiality, integrity, and availability.

Affected products:
- ABAP Developer Tools

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-120009

## CVE-2026-120010

SAP NetWeaver Application Server (SAP Message Server) is vulnerable to a heap buffer overflow due to improper memory allocation sizing when processing specific HTTP requests. An unauthenticated remote attacker can exploit this vulnerability to cause a system crash, leading to a denial-of-service condition affecting system availability. There is no impact on data confidentiality or integrity.

Affected products:
- NetWeaver Application Server

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-120010

## CVE-2026-120014

SAP HANA XSA Web Dispatcher contains a vulnerability involving insufficient request validation in administrative functionality. An unauthenticated attacker can leverage this via a Cross-Site Request Forgery (CSRF) style attack by tricking an authenticated administrator into clicking a malicious link, potentially leading to unauthorized actions within the administrative session.

Affected products:
- HANA XSA Web Dispatcher

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-120014

## CVE-2026-120015

SAP Host Agent fails to properly validate inputs, allowing a low-privileged local attacker to influence an internal component to load a malicious file with privileged account permissions. This vulnerability can be leveraged to achieve persistent code execution, compromising the confidentiality, integrity, and availability of the affected system.

Affected products:
- Host Agent

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-120015

## CVE-2026-76966

SAP Kernel used by the Application Server ABAP of SAP NetWeaver and ABAP Platform is vulnerable to memory corruption due to improper RFC protocol validation. An unauthenticated attacker can send a crafted RFC request to exploit logical errors in memory management, impacting confidentiality and integrity.

Affected products:
- SAP NetWeaver
- ABAP Platform

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76966
