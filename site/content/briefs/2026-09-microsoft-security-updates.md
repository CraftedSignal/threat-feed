---
title: Microsoft Security Updates - September 2026
slug: 2026-09-microsoft-security-updates
description: Roundup of Microsoft security advisories published in September 2026.
date: "2026-09-03T23:23:58Z"
lastmod: "2026-09-08T19:32:32Z"
type: threat
types:
  - threat
severities:
  - high
cpes:
  - cpe:2.3:a:microsoft:entra_id:-:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:fabric:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_11_26h1:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_11_26h1:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:power_platform:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:arm64:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
tags:
  - roundup
vendors:
  - Microsoft
cves:
  - id: CVE-2026-62916
    product: Entra ID
    cvss: 9.1
    epss: 0.00582
  - id: CVE-2026-70352
    product: Azure AI Language
    cvss: 10
    epss: 0.00623
  - id: CVE-2026-83711
    product: Azure Active Directory B2C
    cvss: 10
    epss: 0.00582
  - id: CVE-2026-65818
    cvss: 8.5
    epss: 0.00329
  - id: CVE-2026-69857
    cvss: 8.5
    epss: 0.00423
  - id: CVE-2026-70178
    cvss: 8.5
    epss: 0.00414
  - id: CVE-2026-81963
    product: Windows
    cvss: 7.8
  - id: CVE-2026-85880
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-70178
updates:
  - at: "2026-09-03T23:24:06Z"
    level: L2
    summary: added CVE-2026-83711
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-83711
  - at: "2026-09-03T23:25:23Z"
    level: L2
    summary: added CVE-2026-62906, CVE-2026-65818
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-62906
      - https://nvd.nist.gov/vuln/detail/CVE-2026-69857
  - at: "2026-09-08T19:32:30Z"
    level: L2
    summary: added CVE-2026-70178 +1
    sources:
      - cisa-kev
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-81963
  - at: "2026-09-08T19:32:32Z"
    level: L2
    summary: added CVE-2026-65818 +2
    sources:
      - cisa-kev
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-85880
---

This roundup covers 9 Microsoft security vulnerabilities. CVSS base scores range from 7.8 to 10.0. None are reported as actively exploited at the time of release. The issues affect Azure AI Language, Azure Active Directory B2C, Azure Cosmos DB, Copilot Studio, Discovery Studio, Entra ID, Fabric, Power Automate, Windows.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-62916](#cve-2026-62916) | Entra ID | Critical | 9.1 | 0.58% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-62916) (authoritative) |
| [CVE-2026-70352](#cve-2026-70352) | Azure AI Language | Critical | 10.0 | 0.62% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70352) (authoritative) |
| [CVE-2026-80098](#cve-2026-80098) | Copilot Studio |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-80098) (authoritative) |
| [CVE-2026-83711](#cve-2026-83711) | Azure Active Directory B2C | Critical | 10.0 | 0.58% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83711) (authoritative) |
| [CVE-2026-62906](#cve-2026-62906) | Discovery Studio |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-62906) (authoritative) |
| [CVE-2026-65818](#cve-2026-65818) | Power Automate |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-65818) (authoritative) |
| [CVE-2026-69857](#cve-2026-69857) | Azure Cosmos DB |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69857) (authoritative) |
| [CVE-2026-70178](#cve-2026-70178) | Fabric | High | 8.5 | 0.41% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70178) (authoritative) |
| [CVE-2026-81963](#cve-2026-81963) | Windows | High | 7.8 |  | no | [source](https://www.cve.org/CVERecord?id=CVE-2026-81963) (authoritative) |


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

## CVE-2026-62906

CVE-2026-62906 describes an improper neutralization of special elements in data query logic within Microsoft Discovery Studio. This vulnerability allows an unauthorized remote attacker to perform unauthorized data disclosure over a network, potentially exposing sensitive information due to flawed query handling.

Affected products:
- Discovery Studio

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-62906

## CVE-2026-65818

CVE-2026-65818 is a server-side request forgery (SSRF) vulnerability in Microsoft Power Automate that enables an authorized attacker to perform privilege escalation over a network.

Affected products:
- Power Automate

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-65818

## CVE-2026-69857

CVE-2026-69857 describes an authorization bypass vulnerability in Azure Cosmos DB, where a user-controlled key allows an already authorized attacker to perform network spoofing, potentially escalating access or manipulating data communication.

Affected products:
- Azure Cosmos DB

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69857

## CVE-2026-70178

CVE-2026-70178 is a privilege escalation vulnerability in Microsoft Fabric caused by a missing authorization check, which allows an attacker with existing network access to gain unauthorized elevated privileges.

Affected products:
- Fabric

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-70178

## CVE-2026-81963

CVE-2026-81963 is a link following vulnerability in the Microsoft Windows Update Stack that allows a local attacker to escalate privileges to SYSTEM. Detection engineers should prioritize patching affected assets in accordance with CISA's BOD 26-04 guidelines.

Affected products:
- Windows

Source: https://www.cve.org/CVERecord?id=CVE-2026-81963
