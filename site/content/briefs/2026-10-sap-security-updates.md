---
title: SAP Security Updates - October 2026
slug: 2026-10-sap-security-updates
description: Roundup of SAP security advisories published in October 2026.
date: "2026-10-13T02:31:31Z"
lastmod: "2026-10-13T02:31:38Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - roundup
vendors:
  - SAP
cves:
  - id: CVE-2026-89107
    product: S/4HANA
    cvss: 9.9
  - id: CVE-2026-89108
    product: Manufacturing Integration and Intelligence
    cvss: 9.1
  - id: CVE-2026-89110
    product: NetWeaver Visual Composer
    cvss: 9.9
  - id: CVE-2026-89111
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89111
updates:
  - at: "2026-10-13T02:31:31Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-89107
  - at: "2026-10-13T02:31:33Z"
    level: L2
    summary: added CVE-2026-89108, CVE-2026-89110, CVE-2026-89111
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-89108
      - https://nvd.nist.gov/vuln/detail/CVE-2026-89110
      - https://nvd.nist.gov/vuln/detail/CVE-2026-89111
---

This roundup covers 3 SAP security vulnerabilities. CVSS base scores range from 9.1 to 9.9. None are reported as actively exploited at the time of release. The issues affect Manufacturing Integration and Intelligence, NetWeaver Visual Composer, S/4HANA.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-89107](#cve-2026-89107) | S/4HANA | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-89107) (authoritative) |
| [CVE-2026-89108](#cve-2026-89108) | Manufacturing Integration and Intelligence | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-89108) (authoritative) |
| [CVE-2026-89110](#cve-2026-89110) | NetWeaver Visual Composer | Critical | 9.9 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-89110) (authoritative) |


## CVE-2026-89107

SAP S/4HANA's 'Manage Substitution/Validation Rules' feature contains a vulnerability where input provided to a domain-specific scripting language is not sufficiently validated. An authenticated attacker with specific privileges can submit crafted input that is interpreted as executable ABAP code, leading to arbitrary code execution and full system compromise.

Affected products:
- S/4HANA

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-89107

## CVE-2026-89108

SAP Manufacturing Integration and Intelligence is vulnerable to a privilege escalation flaw where an attacker with administrative privileges can execute specially crafted requests to create new accounts with elevated privileges on the underlying Java application server, potentially leading to full system compromise.

Affected products:
- Manufacturing Integration and Intelligence

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-89108

## CVE-2026-89110

SAP NetWeaver Visual Composer contains an authorization bypass vulnerability allowing low-privileged authenticated users to trigger internal operations on preconfigured remote systems. Successful exploitation can lead to full remote system compromise, impacting confidentiality, integrity, and availability.

Affected products:
- NetWeaver Visual Composer

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-89110
