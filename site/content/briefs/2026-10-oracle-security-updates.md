---
brief_id: brief-2026-10-oracle-security-updates
event_id: brief-2026-10-oracle-security-updates
revision: 7
activity_at: "2026-10-21T00:10:40Z"
revision_history:
  - revision: 2
    at: "2026-10-21T00:10:35Z"
    checksum: sha256:365640cf04a9924b769d8c825d9fdb5a8ff6a0f746bc055d12a71c2c814a72cf
    summary: added CVE-2026-101484
    changed_fields:
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101484
  - revision: 3
    at: "2026-10-21T00:10:36Z"
    checksum: sha256:e42d0de5be7de9c2b0b5a626703c07f6a6f4b82c0a20d761f05e6d649e709fae
    summary: added CVE-2026-101484, CVE-2026-101499
    changed_fields:
      - content
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101484
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101499
  - revision: 4
    at: "2026-10-21T00:10:37Z"
    checksum: sha256:e46de117e46308ea7d167b8a653818c3e5e6fff1d9ce0d88490f55b4404f6cba
    summary: added CVE-2026-101484, CVE-2026-101499, CVE-2026-101501
    changed_fields:
      - content
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101484
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101499
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101501
  - revision: 5
    at: "2026-10-21T00:10:38Z"
    checksum: sha256:72334588c13bc8213e4e43d8c3ed15773009612d564f22875a2fc580f35f2cb6
    summary: added CVE-2026-101484 +3
    changed_fields:
      - content
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101484
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101499
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101501
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101503
  - revision: 6
    at: "2026-10-21T00:10:39Z"
    checksum: sha256:4aab264e8d253212781993e8af879fbb275d85717f38e0eb0bc7ddef9d02d09b
    summary: added CVE-2026-101521
    changed_fields:
      - content
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101521
  - revision: 7
    at: "2026-10-21T00:10:40Z"
    checksum: sha256:87bf09ac0dcc39f6a39802f8dadb5f5b139261cfc39713d33caea5668b892e94
    summary: added CVE-2026-101521, CVE-2026-101529
    changed_fields:
      - content
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101521
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101537
title: Oracle Security Updates - October 2026
slug: 2026-10-oracle-security-updates
description: Roundup of Oracle security advisories published in October 2026.
date: "2026-10-21T00:09:53Z"
lastmod: "2026-10-21T00:10:03Z"
type: threat
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
tags:
  - roundup
vendors:
  - Oracle
cves:
  - id: CVE-2026-101446
    product: Siebel CRM Cloud Applications (17.0-26.9)
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-101484
    product: Secure Backup (19.1.0.0.0, 19.1.0.1.0)
    cvss: 9.8
    kev_status: "false"
  - id: CVE-2026-101499
    product: WebCenter Sites (12.2.1.4.0, 14.1.2.0.0)
    cvss: 9.8
    kev_status: "false"
  - id: CVE-2026-101501
    product: Trusted Answer Search (26.1)
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-101503
    product: Trusted Answer Search (26.1)
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-101521
    product: APEX (24.1.0-24.1.21, 24.2.0-24.2.20, 26.1.0-26.1.4)
    cvss: 9.8
    kev_status: "false"
  - id: CVE-2026-101529
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-101537
    kev_status: unknown
  - id: CVE-2026-101528
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101537
updates:
  - at: "2026-10-21T00:09:55Z"
    level: L2
    summary: added CVE-2026-101499, CVE-2026-101501, CVE-2026-101503
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101499
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101501
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101503
  - at: "2026-10-21T00:10:00Z"
    level: L2
    summary: added CVE-2026-101521, CVE-2026-101529
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101521
      - https://nvd.nist.gov/vuln/detail/CVE-2026-101537
---

This roundup covers 8 Oracle security vulnerabilities. CVSS base scores range from 9.8 to 9.9. None are reported as actively exploited at the time of release. The issues affect APEX, Enterprise Manager for Oracle Database, Secure Backup, Siebel CRM Cloud Applications, Trusted Answer Search, WebCenter Sites.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-101446](#cve-2026-101446) | Siebel CRM Cloud Applications (17.0-26.9) | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-101446) (authoritative) |
| [CVE-2026-101484](#cve-2026-101484) | Secure Backup (19.1.0.0.0, 19.1.0.1.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-101484) (authoritative) |
| [CVE-2026-101499](#cve-2026-101499) | WebCenter Sites (12.2.1.4.0, 14.1.2.0.0) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-101499) (authoritative) |
| [CVE-2026-101501](#cve-2026-101501) | Trusted Answer Search (26.1) | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-101501) (authoritative) |
| [CVE-2026-101503](#cve-2026-101503) | Trusted Answer Search (26.1) | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-101503) (authoritative) |
| [CVE-2026-101521](#cve-2026-101521) | APEX (24.1.0-24.1.21, 24.2.0-24.2.20, 26.1.0-26.1.4) | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-101521) (authoritative) |
| [CVE-2026-101528](#cve-2026-101528) | n/a |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-101528) (authoritative) |
| [CVE-2026-101529](#cve-2026-101529) | Enterprise Manager for Oracle Database (13.5, 24.1) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-101529) (authoritative) |


## CVE-2026-101446

CVE-2026-101446 is a critical vulnerability in Oracle Siebel CRM Cloud Applications (specifically the Siebel Cloud Manager component) affecting versions 17.0 through 26.9. The flaw allows a low-privileged, network-adjacent attacker to achieve full system takeover via HTTP requests. Due to the high CVSS score of 9.9 and the potential for scope change, this vulnerability poses a severe risk of compromising the confidentiality, integrity, and availability of the application.

Affected products:
- Siebel CRM Cloud Applications (17.0-26.9)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-101446

## CVE-2026-101484

CVE-2026-101484 is a critical vulnerability in Oracle Secure Backup's Backup and Restore component affecting versions 19.1.0.0.0 and 19.1.0.1.0. An unauthenticated attacker with network access via TCP can exploit this flaw to achieve full system takeover, resulting in a CVSS score of 9.8.

Affected products:
- Secure Backup (19.1.0.0.0, 19.1.0.1.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-101484

## CVE-2026-101499

Oracle WebCenter Sites versions 12.2.1.4.0 and 14.1.2.0.0 contain a critical vulnerability allowing unauthenticated remote attackers to achieve full system takeover via HTTP requests. The vulnerability is highly exploitable with low attack complexity, requiring no user interaction and having high impact on confidentiality, integrity, and availability.

Affected products:
- WebCenter Sites (12.2.1.4.0, 14.1.2.0.0)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-101499

## CVE-2026-101501

CVE-2026-101501 is a critical vulnerability in the PLSQL package of Oracle Trusted Answer Search version 26.1. A low-privileged attacker with network access via Oracle Net can exploit this vulnerability to achieve unauthorized read, write, and deletion of data, as well as cause a denial-of-service (hang or crash). The vulnerability involves a scope change, meaning it can impact other products in the environment.

Affected products:
- Trusted Answer Search (26.1)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-101501




Related in this roundup: [CVE-2026-101503](#cve-2026-101503).

## CVE-2026-101503

CVE-2026-101503 is a critical, easily exploitable vulnerability in the PLSQL package of Oracle Trusted Answer Search version 26.1. A low-privileged attacker with network access via Oracle Net can compromise the application, potentially resulting in full system takeover and impacting the confidentiality, integrity, and availability of the target environment. The vulnerability includes a scope change, meaning exploitation can affect additional products beyond the primary target.

Affected products:
- Trusted Answer Search (26.1)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-101503




Related in this roundup: [CVE-2026-101501](#cve-2026-101501).

## CVE-2026-101521

Oracle APEX is vulnerable to an unauthenticated, remotely exploitable issue that allows a network-based attacker to fully compromise the application. The vulnerability has a CVSS 3.1 base score of 9.8, indicating severe impact on confidentiality, integrity, and availability.

Affected products:
- APEX (24.1.0-24.1.21, 24.2.0-24.2.20, 26.1.0-26.1.4)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-101521

## CVE-2026-101528

CVE-2026-101528 is a critical vulnerability in the Data Guard Management component of Oracle Enterprise Manager for Oracle Database. The vulnerability is network-exploitable via HTTP by a low-privileged attacker, potentially leading to a full system takeover and impacting other products due to a scope change (CVSS 9.9).

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-101528

## CVE-2026-101529

CVE-2026-101529 is a critical vulnerability in the Data Guard Management component of Oracle Enterprise Manager for Oracle Database (versions 13.5 and 24.1). An attacker with low-level privileges can exploit this vulnerability over HTTP to achieve a full system compromise. The vulnerability is characterized by a scope change, allowing the attack to impact additional products, and holds a CVSS 3.1 base score of 9.9.

Affected products:
- Enterprise Manager for Oracle Database (13.5, 24.1)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-101529
