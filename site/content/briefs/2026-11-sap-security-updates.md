---
brief_id: brief-2026-11-sap-security-updates
event_id: brief-2026-11-sap-security-updates
revision: 1
activity_at: "2026-11-10T02:00:57Z"
title: SAP Security Updates - November 2026
slug: 2026-11-sap-security-updates
description: Roundup of SAP security advisories published in November 2026.
date: "2026-11-10T02:00:57Z"
lastmod: "2026-11-10T02:01:22Z"
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
    cvss: 9.6
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89119
updates:
  - at: "2026-11-10T02:01:01Z"
    level: L2
    summary: added CVE-2026-109803, CVE-2026-120017, CVE-2026-76964
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-109803
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120017
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76964
  - at: "2026-11-10T02:01:18Z"
    level: L2
    summary: added CVE-2026-76965 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-89103
  - at: "2026-11-10T02:01:22Z"
    level: L2
    summary: added CVE-2026-89119
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-89119
---

This roundup covers 7 SAP security vulnerabilities. CVSS base scores range from 9.1 to 10.0. None are reported as actively exploited at the time of release. The issues affect BusinessObjects Business Intelligence Platform, NetWeaver, NetWeaver AS ABAP, NetWeaver Application Server ABAP, NetWeaver Knowledge Management, SAP Gateway.

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


## CVE-2026-109795

SAP NetWeaver contains a critical vulnerability where remote-enabled functionality lacks proper authorization checks and input validation. A low-privileged attacker can leverage this flaw to inject and execute arbitrary code, potentially leading to full compromise of system confidentiality, integrity, and availability.

Affected products:
- NetWeaver

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-109795

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


Related in this roundup: [CVE-2026-76965](#cve-2026-76965).

## CVE-2026-76965

SAP NetWeaver Application Server ABAP and ABAP Platform contain an authorization bypass vulnerability allowing low-privileged authenticated users to execute arbitrary operating system commands. The lack of proper authorization checks for internal functionality facilitates remote code execution (RCE) with high impact on confidentiality, integrity, and availability.

Affected products:
- NetWeaver Application Server ABAP
- ABAP Platform

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-76965


Related in this roundup: [CVE-2026-76964](#cve-2026-76964).

## CVE-2026-89103

SAP Gateway contains a vulnerability where the default Access Control List (ACL) is configured with excessive privileges. This allows an unauthenticated, network-adjacent attacker to be miscategorized as an internal application server, potentially enabling unauthorized actions that compromise the confidentiality, integrity, and availability of the SAP environment.

Affected products:
- SAP Gateway

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-89103
