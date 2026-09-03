---
title: Microsoft Security Updates - September 2026
slug: 2026-09-microsoft-security-updates
description: Roundup of Microsoft security advisories published in September 2026.
date: "2026-09-03T23:23:58Z"
lastmod: "2026-09-03T23:25:23Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - roundup
vendors:
  - Microsoft
cves:
  - id: CVE-2026-62916
    product: Entra ID
    cvss: 9.1
  - id: CVE-2026-70352
    product: Azure AI Language
    cvss: 10
  - id: CVE-2026-80098
    product: Copilot Studio
    cvss: 9.3
  - id: CVE-2026-83711
    product: Azure Active Directory B2C
    cvss: 10
  - id: CVE-2026-62906
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62906
updates:
  - at: "2026-09-03T23:23:58Z"
    level: L1
    summary: posted roundup
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-62916
  - at: "2026-09-03T23:24:01Z"
    level: L2
    summary: added CVE-2026-70352, CVE-2026-80098, CVE-2026-83711
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-70352
      - https://nvd.nist.gov/vuln/detail/CVE-2026-80098
      - https://nvd.nist.gov/vuln/detail/CVE-2026-83711
  - at: "2026-09-03T23:25:23Z"
    level: L2
    summary: added CVE-2026-62906
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-62906
---

This roundup covers 4 Microsoft security vulnerabilities. CVSS base scores range from 9.1 to 10.0. None are reported as actively exploited at the time of release. The issues affect Azure AI Language, Azure Active Directory B2C, Copilot Studio, Entra ID.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-62916](#cve-2026-62916) | Entra ID | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-62916) (authoritative) |
| [CVE-2026-70352](#cve-2026-70352) | Azure AI Language | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70352) (authoritative) |
| [CVE-2026-80098](#cve-2026-80098) | Copilot Studio | Critical | 9.3 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-80098) (authoritative) |
| [CVE-2026-83711](#cve-2026-83711) | Azure Active Directory B2C | Critical | 10.0 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83711) (authoritative) |


## CVE-2026-62916

CVE-2026-62916 is an authentication bypass vulnerability in Microsoft Entra ID arising from the use of an alternate path or channel. This vulnerability permits an unauthorized remote attacker to perform privilege escalation within the identity management environment.

Affected products:
- Entra ID

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-62916

## CVE-2026-70352

CVE-2026-70352 describes a critical vulnerability in Microsoft's Azure AI Language service where a missing authentication control on a critical function allows an unauthorized remote attacker to perform privilege escalation. The vulnerability carries a CVSS base score of 10.0, indicating high severity and potential for exploitation over a network.

Affected products:
- Azure AI Language

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-70352

## CVE-2026-80098

CVE-2026-80098 is a vulnerability in Microsoft Copilot Studio involving improper verification of cryptographic signatures. This flaw allows an unauthorized attacker to perform a privilege escalation attack over a network, presenting a significant security risk given its high CVSS base score.

Affected products:
- Copilot Studio

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-80098

## CVE-2026-83711

An authorization bypass vulnerability exists in Microsoft Azure Active Directory B2C due to improper handling of user-controlled keys. An unauthenticated attacker can exploit this flaw over the network to elevate privileges, leading to a critical security impact.

Affected products:
- Azure Active Directory B2C

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-83711
