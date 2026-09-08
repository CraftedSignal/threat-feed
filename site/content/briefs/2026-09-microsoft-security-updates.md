---
title: Microsoft Security Updates - September 2026
slug: 2026-09-microsoft-security-updates
description: Roundup of Microsoft security advisories published in September 2026.
date: "2026-09-03T23:23:58Z"
lastmod: "2026-09-08T19:43:20Z"
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
  - cpe:2.3:a:microsoft:copilot_studio:-:*:*:*:*:*:*:*
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
  - id: CVE-2026-80098
    cvss: 9.3
    epss: 0.00293
  - id: CVE-2026-83711
    product: Azure Active Directory B2C
    cvss: 10
    epss: 0.00582
  - id: CVE-2026-62906
    cvss: 7.4
    epss: 0.00666
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
    product: Windows
    cvss: 7.8
  - id: CVE-2026-65669
    cvss: 9.6
  - id: CVE-2026-68839
    cvss: 9.8
  - id: CVE-2026-69276
    cvss: 9.8
  - id: CVE-2026-69408
    cvss: 9.8
  - id: CVE-2026-69493
    cvss: 9.8
  - id: CVE-2026-69579
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69579
updates:
  - at: "2026-09-08T19:42:55Z"
    level: L2
    summary: added CVE-2026-65669 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-69356
  - at: "2026-09-08T19:42:58Z"
    level: L2
    summary: added CVE-2026-69276
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-69408
  - at: "2026-09-08T19:43:13Z"
    level: L2
    summary: added CVE-2026-69408, CVE-2026-69493, CVE-2026-69579
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-69493
      - https://nvd.nist.gov/vuln/detail/CVE-2026-69496
      - https://nvd.nist.gov/vuln/detail/CVE-2026-69579
---

This roundup covers 20 Microsoft security vulnerabilities. CVSS base scores range from 7.4 to 10.0. None are reported as actively exploited at the time of release. The issues affect Azure AI Language, Azure Active Directory B2C, Azure Cosmos DB, Copilot Studio, DirectMusic, Discovery Studio, Entra ID, Exchange Server, Fabric, NTFS, Power Automate, Remote Desktop Services, SQL Server, UxTheme Library, Windows, Windows Event Logging Service, Windows Media Foundation, Windows USB Mass Storage Class Driver.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-62916](#cve-2026-62916) | Entra ID | Critical | 9.1 | 0.58% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-62916) (authoritative) |
| [CVE-2026-70352](#cve-2026-70352) | Azure AI Language | Critical | 10.0 | 0.62% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70352) (authoritative) |
| [CVE-2026-80098](#cve-2026-80098) | Copilot Studio | Critical | 9.3 | 0.29% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-80098) (authoritative) |
| [CVE-2026-83711](#cve-2026-83711) | Azure Active Directory B2C | Critical | 10.0 | 0.58% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-83711) (authoritative) |
| [CVE-2026-62906](#cve-2026-62906) | Discovery Studio | High | 7.4 | 0.67% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-62906) (authoritative) |
| [CVE-2026-65818](#cve-2026-65818) | Power Automate | High | 8.5 | 0.33% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-65818) (authoritative) |
| [CVE-2026-69857](#cve-2026-69857) | Azure Cosmos DB | High | 8.5 | 0.42% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69857) (authoritative) |
| [CVE-2026-70178](#cve-2026-70178) | Fabric | High | 8.5 | 0.41% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70178) (authoritative) |
| [CVE-2026-81963](#cve-2026-81963) | Windows | High | 7.8 |  | no | [source](https://www.cve.org/CVERecord?id=CVE-2026-81963) (authoritative) |
| [CVE-2026-85880](#cve-2026-85880) | Windows | High | 7.8 |  | no | [source](https://www.cve.org/CVERecord?id=CVE-2026-85880) (authoritative) |
| [CVE-2026-65669](#cve-2026-65669) | SQL Server | Critical | 9.6 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-65669) (authoritative) |
| [CVE-2026-68839](#cve-2026-68839) | Windows USB Mass Storage Class Driver | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-68839) (authoritative) |
| [CVE-2026-69276](#cve-2026-69276) | UxTheme Library | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69276) (authoritative) |
| [CVE-2026-69356](#cve-2026-69356) | Exchange Server |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69356) (authoritative) |
| [CVE-2026-69408](#cve-2026-69408) | Windows Media Foundation | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69408) (authoritative) |
| [CVE-2026-69463](#cve-2026-69463) | NTFS |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69463) (authoritative) |
| [CVE-2026-69491](#cve-2026-69491) | DirectMusic |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69491) (authoritative) |
| [CVE-2026-69493](#cve-2026-69493) | Windows Event Logging Service | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69493) (authoritative) |
| [CVE-2026-69496](#cve-2026-69496) | Windows |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69496) (authoritative) |
| [CVE-2026-69525](#cve-2026-69525) | Remote Desktop Services |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69525) (authoritative) |


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











Related in this roundup: [CVE-2026-85880](#cve-2026-85880), [CVE-2026-69496](#cve-2026-69496).

## CVE-2026-85880

A heap-based buffer overflow vulnerability exists in the Microsoft Windows Advanced Local Procedure Call (ALPC) component, which can be exploited by a local attacker to achieve privilege escalation.

Affected products:
- Windows

Source: https://www.cve.org/CVERecord?id=CVE-2026-85880











Related in this roundup: [CVE-2026-81963](#cve-2026-81963), [CVE-2026-69496](#cve-2026-69496).

## CVE-2026-65669

CVE-2026-65669 describes an injection vulnerability in Microsoft SQL Server that allows an unauthorized network-based attacker to escalate privileges. The vulnerability stems from improper neutralization of special elements in output used by a downstream component.

Affected products:
- SQL Server

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-65669

## CVE-2026-68839

CVE-2026-68839 is a heap-based buffer overflow vulnerability within the Windows USB Mass Storage Class Driver. An unauthorized remote attacker can exploit this flaw to achieve remote code execution, indicating a significant security risk for Windows systems that interact with malicious USB mass storage devices over a network context.

Affected products:
- Windows USB Mass Storage Class Driver

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-68839

## CVE-2026-69276

CVE-2026-69276 describes an integer underflow vulnerability within the Microsoft UxTheme Library (uxtheme.dll). An unauthenticated attacker can exploit this flaw to achieve remote code execution over a network, carrying a CVSS base score of 9.8.

Affected products:
- UxTheme Library

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69276

## CVE-2026-69356

CVE-2026-69356 describes a cross-site scripting (XSS) vulnerability in Microsoft Exchange Server resulting from improper input neutralization. This flaw enables an unauthorized network-based attacker to perform spoofing activities by injecting malicious content into generated web pages.

Affected products:
- Exchange Server

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69356

## CVE-2026-69408

CVE-2026-69408 describes an integer overflow or wraparound vulnerability within the Microsoft Windows Media Foundation component. This flaw can be exploited by a remote, unauthorized attacker to achieve remote code execution (RCE) over a network, presenting a high risk as indicated by a CVSS v3.1 base score of 9.8.

Affected products:
- Windows Media Foundation

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69408

## CVE-2026-69463

CVE-2026-69463 is a heap-based buffer overflow vulnerability located in the Windows NTFS implementation. The vulnerability allows an unauthorized attacker to achieve remote code execution over a network, carrying a CVSS v3.1 base score of 9.8.

Affected products:
- NTFS

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69463

## CVE-2026-69491

CVE-2026-69491 is a critical heap-based buffer overflow vulnerability within the Microsoft DirectMusic component of Windows. An unauthenticated attacker can exploit this flaw remotely over a network to achieve arbitrary code execution on the target system.

Affected products:
- DirectMusic

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69491

## CVE-2026-69493

CVE-2026-69493 describes an out-of-bounds read vulnerability in the Windows Event Logging Service that can be exploited by an unauthorized remote attacker to achieve remote code execution. The vulnerability is rated with a CVSS v3.1 base score of 9.8, indicating a critical severity due to the potential for network-based exploitation.

Affected products:
- Windows Event Logging Service

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69493

## CVE-2026-69496

CVE-2026-69496 is a heap-based buffer overflow vulnerability within the Windows Compressed Folder feature. This vulnerability allows an unauthenticated, remote attacker to achieve remote code execution on an affected system via network-based exploitation.

Affected products:
- Windows

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69496


Related in this roundup: [CVE-2026-81963](#cve-2026-81963), [CVE-2026-85880](#cve-2026-85880).

## CVE-2026-69525

CVE-2026-69525 is a critical use-after-free vulnerability in Microsoft Windows Remote Desktop Services that can be exploited by an unauthenticated attacker to achieve remote code execution over a network with a CVSS v3.1 score of 9.8.

Affected products:
- Remote Desktop Services

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69525
