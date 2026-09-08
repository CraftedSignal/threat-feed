---
title: Microsoft Security Updates - September 2026
slug: 2026-09-microsoft-security-updates
description: Roundup of Microsoft security advisories published in September 2026.
date: "2026-09-03T23:23:58Z"
lastmod: "2026-09-08T19:45:10Z"
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
  - id: CVE-2026-69356
    cvss: 9.3
  - id: CVE-2026-69408
    cvss: 9.8
  - id: CVE-2026-69493
    cvss: 9.8
  - id: CVE-2026-69525
    cvss: 9.8
  - id: CVE-2026-69579
    product: Windows Message Queuing
    cvss: 9.8
  - id: CVE-2026-69590
    cvss: 9.8
  - id: CVE-2026-69641
    cvss: 9.1
  - id: CVE-2026-69715
    product: Direct Show
    cvss: 9.8
  - id: CVE-2026-69768
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69845
updates:
  - at: "2026-09-08T19:43:25Z"
    level: L2
    summary: added CVE-2026-69356, CVE-2026-69590, CVE-2026-69715
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-69590
      - https://nvd.nist.gov/vuln/detail/CVE-2026-69715
      - https://nvd.nist.gov/vuln/detail/CVE-2026-69768
  - at: "2026-09-08T19:45:07Z"
    level: L2
    summary: added CVE-2026-69525 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-69829
  - at: "2026-09-08T19:45:10Z"
    level: L2
    summary: added CVE-2026-69768
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-69845
---

This roundup covers 31 Microsoft security vulnerabilities. CVSS base scores range from 7.4 to 10.0. None are reported as actively exploited at the time of release. The issues affect Azure AI Language, Azure Active Directory B2C, Azure Cosmos DB, Copilot Studio, Direct Show, DirectMusic, Discovery Studio, Entra ID, Exchange Server, Fabric, NTFS, Power Automate, Remote Desktop Services, Routing and Remote Access Service, SQL Server, Standard XPS, UxTheme Library, Windows, Windows DNS, Windows Event Logging Service, Windows HTTP Print Provider, Windows Media Foundation, Windows Message Queuing, Windows Services for NFS, Windows Shell, Windows USB Mass Storage Class Driver.

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
| [CVE-2026-69356](#cve-2026-69356) | Exchange Server | Critical | 9.3 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69356) (authoritative) |
| [CVE-2026-69408](#cve-2026-69408) | Windows Media Foundation | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69408) (authoritative) |
| [CVE-2026-69463](#cve-2026-69463) | NTFS |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69463) (authoritative) |
| [CVE-2026-69491](#cve-2026-69491) | DirectMusic |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69491) (authoritative) |
| [CVE-2026-69493](#cve-2026-69493) | Windows Event Logging Service | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69493) (authoritative) |
| [CVE-2026-69496](#cve-2026-69496) | Windows |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69496) (authoritative) |
| [CVE-2026-69525](#cve-2026-69525) | Remote Desktop Services | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69525) (authoritative) |
| [CVE-2026-69579](#cve-2026-69579) | Windows Message Queuing | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69579) (authoritative) |
| [CVE-2026-69586](#cve-2026-69586) | Windows |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69586) (authoritative) |
| [CVE-2026-69590](#cve-2026-69590) | Routing and Remote Access Service | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69590) (authoritative) |
| [CVE-2026-69595](#cve-2026-69595) | Windows Services for NFS |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69595) (authoritative) |
| [CVE-2026-69641](#cve-2026-69641) | Exchange Server | Critical | 9.1 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69641) (authoritative) |
| [CVE-2026-69715](#cve-2026-69715) | Direct Show | Critical | 9.8 |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69715) (authoritative) |
| [CVE-2026-69730](#cve-2026-69730) | Windows DNS |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69730) (authoritative) |
| [CVE-2026-69768](#cve-2026-69768) | Windows |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69768) (authoritative) |
| [CVE-2026-69769](#cve-2026-69769) | Windows HTTP Print Provider |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69769) (authoritative) |
| [CVE-2026-69824](#cve-2026-69824) | Standard XPS |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69824) (authoritative) |
| [CVE-2026-69829](#cve-2026-69829) | Windows Shell |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-69829) (authoritative) |


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






















Related in this roundup: [CVE-2026-85880](#cve-2026-85880), [CVE-2026-69496](#cve-2026-69496), [CVE-2026-69586](#cve-2026-69586), [CVE-2026-69768](#cve-2026-69768).

## CVE-2026-85880

A heap-based buffer overflow vulnerability exists in the Microsoft Windows Advanced Local Procedure Call (ALPC) component, which can be exploited by a local attacker to achieve privilege escalation.

Affected products:
- Windows

Source: https://www.cve.org/CVERecord?id=CVE-2026-85880






















Related in this roundup: [CVE-2026-81963](#cve-2026-81963), [CVE-2026-69496](#cve-2026-69496), [CVE-2026-69586](#cve-2026-69586), [CVE-2026-69768](#cve-2026-69768).

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







Related in this roundup: [CVE-2026-69641](#cve-2026-69641).

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













Related in this roundup: [CVE-2026-81963](#cve-2026-81963), [CVE-2026-85880](#cve-2026-85880), [CVE-2026-69586](#cve-2026-69586), [CVE-2026-69768](#cve-2026-69768).

## CVE-2026-69525

CVE-2026-69525 is a critical use-after-free vulnerability in Microsoft Windows Remote Desktop Services that can be exploited by an unauthenticated attacker to achieve remote code execution over a network with a CVSS v3.1 score of 9.8.

Affected products:
- Remote Desktop Services

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69525

## CVE-2026-69579

A use-after-free vulnerability in Windows Message Queuing enables an unauthorized remote attacker to execute arbitrary code. The vulnerability allows for exploitation over the network with a CVSS score of 9.8, indicating a critical severity level requiring immediate patching.

Affected products:
- Windows Message Queuing

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69579

## CVE-2026-69586

CVE-2026-69586 describes an integer overflow or wraparound vulnerability within the Microsoft Windows PDF component. This flaw permits an unauthorized remote attacker to execute arbitrary code over the network, carrying a high CVSS base score of 9.8.

Affected products:
- Windows

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69586










Related in this roundup: [CVE-2026-81963](#cve-2026-81963), [CVE-2026-85880](#cve-2026-85880), [CVE-2026-69496](#cve-2026-69496), [CVE-2026-69768](#cve-2026-69768).

## CVE-2026-69590

CVE-2026-69590 describes a critical Remote Code Execution (RCE) vulnerability within the Microsoft Windows Routing and Remote Access Service (RRAS). An unauthenticated attacker can exploit this flaw to execute arbitrary code with elevated privileges on the target system, potentially leading to a full system compromise. The vulnerability is characterized by a CVSS v3.1 base score of 9.8, indicating high severity.

Affected products:
- Routing and Remote Access Service

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69590

## CVE-2026-69595

CVE-2026-69595 describes a use-after-free vulnerability in the Windows Services for NFS ONCRPC XDR driver. An unauthorized remote attacker can exploit this flaw to execute arbitrary code with elevated privileges, resulting in a CVSS v3.1 base score of 9.8.

Affected products:
- Windows Services for NFS

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69595

## CVE-2026-69641

CVE-2026-69641 is a privilege escalation vulnerability in Microsoft Exchange Server resulting from a missing authorization check. An attacker who has already gained authorized access to the network can exploit this flaw to elevate their privileges, potentially gaining administrative control over the affected server instance.

Affected products:
- Exchange Server

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69641







Related in this roundup: [CVE-2026-69356](#cve-2026-69356).

## CVE-2026-69715

CVE-2026-69715 is an out-of-bounds read vulnerability in the Windows Direct Show component. This flaw can be exploited by an unauthorized remote attacker to achieve remote code execution over a network, presenting a critical risk to affected Windows systems.

Affected products:
- Direct Show

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69715

## CVE-2026-69730

CVE-2026-69730 is a critical use-after-free vulnerability in the Windows DNS component that allows remote, unauthenticated attackers to achieve remote code execution (RCE) over the network. With a CVSS base score of 9.8, this flaw poses a significant risk to the integrity and availability of affected Windows systems by allowing potential full system compromise.

Affected products:
- Windows DNS

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69730

## CVE-2026-69768

A heap-based buffer overflow vulnerability exists in the Windows Remote Network Driver Interface Specification (RNDIS) implementation. An unauthenticated attacker can exploit this flaw by sending specifically crafted network traffic, potentially leading to remote code execution on the target Windows system.

Affected products:
- Windows

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69768




Related in this roundup: [CVE-2026-81963](#cve-2026-81963), [CVE-2026-85880](#cve-2026-85880), [CVE-2026-69496](#cve-2026-69496), [CVE-2026-69586](#cve-2026-69586).

## CVE-2026-69769

CVE-2026-69769 describes a heap-based buffer overflow vulnerability in the Windows HTTP Print Provider, which can be exploited by an unauthorized remote attacker to achieve arbitrary code execution. The vulnerability is highly critical with a CVSS base score of 9.8, indicating the potential for unauthenticated network-based exploitation.

Affected products:
- Windows HTTP Print Provider

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69769

## CVE-2026-69824

An integer underflow vulnerability exists in Microsoft Standard XPS that allows a remote, unauthorized attacker to execute arbitrary code over a network. The vulnerability is classified as a critical security flaw due to the potential for remote code execution.

Affected products:
- Standard XPS

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69824

## CVE-2026-69829

CVE-2026-69829 is a critical heap-based buffer overflow vulnerability within the Windows Shell component. The vulnerability allows an unauthenticated remote attacker to achieve arbitrary code execution on the target system by sending a specially crafted request over the network.

Affected products:
- Windows Shell

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-69829
