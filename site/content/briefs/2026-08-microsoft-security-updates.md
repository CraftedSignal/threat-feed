---
title: Microsoft Security Updates — August 2026
slug: 2026-08-microsoft-security-updates
description: Roundup of Microsoft security advisories published in August 2026.
date: "2026-08-01T01:41:40Z"
lastmod: "2026-08-11T17:50:04Z"
type: threat
types:
  - threat
severities:
  - high
cpes:
  - cpe:2.3:a:microsoft:azure_confidential_ledger:-:*:*:*:*:*:*:*
tags:
  - roundup
vendors:
  - Microsoft
cves:
  - id: CVE-2026-68823
    cvss: 9.1
    epss: 0.005
  - id: CVE-2026-64590
    epss: 0.00156
  - id: CVE-2026-68187
    epss: 0.00209
  - id: CVE-2026-68152
    epss: 0.00175
  - id: CVE-2026-68118
    epss: 0.00166
  - id: CVE-2026-68317
    epss: 0.00168
  - id: CVE-2026-68401
    epss: 0.00173
  - id: CVE-2026-68327
    epss: 0.00168
  - id: CVE-2026-68132
    epss: 0.00173
  - id: CVE-2026-64523
    cvss: 9.8
    epss: 0.00359
  - id: CVE-2026-62827
    cvss: 8.8
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-63516
updates:
  - at: "2026-08-11T17:49:34Z"
    level: L2
    summary: added CVE-2026-68152, CVE-2026-68823
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62829
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62827
  - at: "2026-08-11T17:49:49Z"
    level: L2
    summary: added CVE-2026-68317 +1
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62837
  - at: "2026-08-11T17:49:58Z"
    level: L2
    summary: added CVE-2026-62827
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-63512
  - at: "2026-08-11T17:50:04Z"
    level: L2
    summary: added CVE-2026-64523
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-63516
---

This roundup covers 75 Microsoft security vulnerabilities. CVSS base scores range from 8.8 to 9.1. None are reported as actively exploited at the time of release. The issues affect AMT, Application Insights Profiler, Azure Active Directory, Azure Confidential Ledger, Azure Logic Apps, Azure SQL Managed Instance, Azure SRE Agent, Azure Service Bus, Bluetooth, Dynamics Business Central, HDF5, Microsoft 365 Admin Center, Microsoft Entra Provisioning Service, Microsoft Planetary Computer Pro, Microsoft Purview eDiscovery, Microsoft Teams, Power Apps, Rpm, SMB Client, SharePoint, SharePoint Online, SharePoint Server, Teams, Visual Studio Code, Windows, Windows Narrator, dma-buf/udmabuf, firmware, ims-pcu, iomap, ksmbd, mctp, net/handshake, pds_core, wanxl.

## Summary

| CVE | Product | Severity | CVSS | EPSS | KEV | Source |
|-----|---------|----------|------|------|-----|--------|
| [CVE-2026-50481](#cve-2026-50481) | Azure Active Directory |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-50481) (authoritative) |
| [CVE-2026-50515](#cve-2026-50515) | Azure Service Bus |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-50515) (authoritative) |
| [CVE-2026-56161](#cve-2026-56161) | Azure Logic Apps |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-56161) (authoritative) |
| [CVE-2026-59115](#cve-2026-59115) | Microsoft Entra Provisioning Service |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-59115) (authoritative) |
| [CVE-2026-59118](#cve-2026-59118) | Power Apps |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-59118) (authoritative) |
| [CVE-2026-62830](#cve-2026-62830) | Azure SRE Agent |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-62830) (authoritative) |
| [CVE-2026-62873](#cve-2026-62873) | Microsoft 365 Admin Center |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-62873) (authoritative) |
| [CVE-2026-62896](#cve-2026-62896) | Microsoft Teams |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-62896) (authoritative) |
| [CVE-2026-63508](#cve-2026-63508) | Microsoft Planetary Computer Pro (GeoCatalog) |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-63508) (authoritative) |
| [CVE-2026-65667](#cve-2026-65667) | Microsoft Teams |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-65667) (authoritative) |
| [CVE-2026-68823](#cve-2026-68823) | Azure Confidential Ledger | Critical | 9.1 | 0.50% | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-68823) (authoritative) |
| [CVE-2026-70332](#cve-2026-70332) | SharePoint Online |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-70332) (authoritative) |
| [CVE-2026-49163](#cve-2026-49163) | Application Insights Profiler |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-49163) (authoritative) |
| [CVE-2026-62836](#cve-2026-62836) | Azure SQL Managed Instance |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-62836) (authoritative) |
| [CVE-2026-62918](#cve-2026-62918) | Microsoft Teams |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-62918) (authoritative) |
| [CVE-2026-65668](#cve-2026-65668) | Microsoft Purview eDiscovery |  |  |  | no | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-65668) (authoritative) |
| [CVE-2026-68480](#cve-2026-68480) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68480) (authoritative) |
| [CVE-2026-64564](#cve-2026-64564) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64564) (authoritative) |
| [CVE-2026-64590](#cve-2026-64590) | dma-buf/udmabuf |  |  | 0.16% | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64590) (authoritative) |
| [CVE-2026-54876](#cve-2026-54876) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-54876) (authoritative) |
| [CVE-2026-44605](#cve-2026-44605) | Rpm |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-44605) (authoritative) |
| [CVE-2026-64573](#cve-2026-64573) | Bluetooth |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64573) (authoritative) |
| [CVE-2026-64565](#cve-2026-64565) | ims-pcu |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64565) (authoritative) |
| [CVE-2026-64578](#cve-2026-64578) | ksmbd |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64578) (authoritative) |
| [CVE-2024-21380](#cve-2024-21380) | Dynamics Business Central |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21380) (authoritative) |
| [CVE-2025-2308](#cve-2025-2308) | HDF5 |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-2308) (authoritative) |
| [CVE-2025-2309](#cve-2025-2309) | HDF5 |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-2309) (authoritative) |
| [CVE-2026-68097](#cve-2026-68097) | ksmbd |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68097) (authoritative) |
| [CVE-2026-68388](#cve-2026-68388) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68388) (authoritative) |
| [CVE-2026-68187](#cve-2026-68187) | n/a |  |  | 0.21% | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68187) (authoritative) |
| [CVE-2026-68152](#cve-2026-68152) | AMT |  |  | 0.18% | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68152) (authoritative) |
| [CVE-2026-68189](#cve-2026-68189) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68189) (authoritative) |
| [CVE-2026-68312](#cve-2026-68312) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68312) (authoritative) |
| [CVE-2026-68130](#cve-2026-68130) | ksmbd |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68130) (authoritative) |
| [CVE-2026-68176](#cve-2026-68176) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68176) (authoritative) |
| [CVE-2026-68145](#cve-2026-68145) | iomap |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68145) (authoritative) |
| [CVE-2026-68318](#cve-2026-68318) | pds_core |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68318) (authoritative) |
| [CVE-2026-68118](#cve-2026-68118) | Windows |  |  | 0.17% | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68118) (authoritative) |
| [CVE-2026-68175](#cve-2026-68175) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68175) (authoritative) |
| [CVE-2026-68328](#cve-2026-68328) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68328) (authoritative) |
| [CVE-2026-68406](#cve-2026-68406) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68406) (authoritative) |
| [CVE-2026-68317](#cve-2026-68317) | Windows |  |  | 0.17% | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68317) (authoritative) |
| [CVE-2026-68099](#cve-2026-68099) | ksmbd |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68099) (authoritative) |
| [CVE-2026-68354](#cve-2026-68354) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68354) (authoritative) |
| [CVE-2026-68326](#cve-2026-68326) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68326) (authoritative) |
| [CVE-2026-68151](#cve-2026-68151) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68151) (authoritative) |
| [CVE-2026-68343](#cve-2026-68343) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68343) (authoritative) |
| [CVE-2026-68184](#cve-2026-68184) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68184) (authoritative) |
| [CVE-2026-68124](#cve-2026-68124) | mctp |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68124) (authoritative) |
| [CVE-2026-68401](#cve-2026-68401) | firmware |  |  | 0.17% | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68401) (authoritative) |
| [CVE-2026-68322](#cve-2026-68322) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68322) (authoritative) |
| [CVE-2026-68214](#cve-2026-68214) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68214) (authoritative) |
| [CVE-2026-68327](#cve-2026-68327) | wanxl |  |  | 0.17% | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68327) (authoritative) |
| [CVE-2026-68188](#cve-2026-68188) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68188) (authoritative) |
| [CVE-2026-68132](#cve-2026-68132) | Windows |  |  | 0.17% | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68132) (authoritative) |
| [CVE-2026-68304](#cve-2026-68304) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68304) (authoritative) |
| [CVE-2026-68098](#cve-2026-68098) | ksmbd |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68098) (authoritative) |
| [CVE-2026-68348](#cve-2026-68348) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68348) (authoritative) |
| [CVE-2026-68195](#cve-2026-68195) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68195) (authoritative) |
| [CVE-2026-68419](#cve-2026-68419) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68419) (authoritative) |
| [CVE-2026-68171](#cve-2026-68171) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68171) (authoritative) |
| [CVE-2026-64523](#cve-2026-64523) | net/handshake |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64523) (authoritative) |
| [CVE-2026-64388](#cve-2026-64388) | SMB Client |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64388) (authoritative) |
| [CVE-2025-37938](#cve-2025-37938) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-37938) (authoritative) |
| [CVE-2026-68207](#cve-2026-68207) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68207) (authoritative) |
| [CVE-2026-50472](#cve-2026-50472) | Windows |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-50472) (authoritative) |
| [CVE-2026-56174](#cve-2026-56174) | Windows Narrator |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-56174) (authoritative) |
| [CVE-2026-58650](#cve-2026-58650) | Visual Studio Code |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58650) (authoritative) |
| [CVE-2026-65768](#cve-2026-65768) | Teams |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-65768) (authoritative) |
| [CVE-2026-57105](#cve-2026-57105) | SharePoint |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-57105) (authoritative) |
| [CVE-2026-62829](#cve-2026-62829) | SharePoint Server |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62829) (authoritative) |
| [CVE-2026-62827](#cve-2026-62827) | SharePoint Server | High | 8.8 |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62827) (authoritative) |
| [CVE-2026-62837](#cve-2026-62837) | SharePoint Server |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62837) (authoritative) |
| [CVE-2026-63514](#cve-2026-63514) | SharePoint Server |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-63514) (authoritative) |
| [CVE-2026-63512](#cve-2026-63512) | SharePoint Server |  |  |  | no | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-63512) (authoritative) |


## CVE-2026-50481

CVE-2026-50481 is a critical vulnerability in Microsoft Azure Active Directory involving the modification of assumed-immutable data (MAID). An authorized attacker can exploit this flaw to escalate privileges within the environment over a network, potentially leading to unauthorized administrative access.

Affected products:
- Azure Active Directory

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-50481

## CVE-2026-50515

CVE-2026-50515 is a critical deserialization of untrusted data vulnerability in Azure Service Bus that permits an authenticated attacker with low privileges to achieve remote code execution. Detection efforts should focus on monitoring anomalous serialized data payloads sent to service bus endpoints and unexpected process execution spawned by the Azure Service Bus service account.

Affected products:
- Azure Service Bus

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-50515

## CVE-2026-56161

CVE-2026-56161 describes an improper access control vulnerability in Microsoft Azure Logic Apps. An authenticated attacker can exploit this vulnerability to disclose sensitive information over a network. The vulnerability carries a CVSS 3.1 base score of 9.6, indicating a critical risk.

Affected products:
- Azure Logic Apps

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-56161

## CVE-2026-59115

CVE-2026-59115 is a critical path traversal vulnerability in the Microsoft Entra Provisioning Service (SyncFabric). An authorized attacker can leverage this vulnerability by using a specific input string ('.../...//') to elevate their privileges over a network. The vulnerability has a CVSS base score of 9.9, indicating a significant risk to the integrity, confidentiality, and availability of the affected cloud service.

Affected products:
- Microsoft Entra Provisioning Service

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-59115

## CVE-2026-59118

CVE-2026-59118 is an improper authorization vulnerability in Microsoft Power Apps that allows an unauthorized attacker to perform a privilege escalation over a network. The vulnerability carries a CVSS 3.1 base score of 9.3, indicating a critical severity impact on confidentiality and integrity, necessitating restricted access controls within the affected cloud service.

Affected products:
- Power Apps

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-59118

## CVE-2026-62830

A vulnerability in the Azure SRE Agent stemming from missing authorization (CWE-862) allows an already authorized network attacker to perform privilege escalation. The vulnerability is rated critical with a CVSS 3.1 score of 9.9, as it enables full scope impact across confidentiality, integrity, and availability within the cloud environment.

Affected products:
- Azure SRE Agent

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-62830

## CVE-2026-62873

The Microsoft 365 Admin Center is vulnerable to an improper verification of cryptographic signature vulnerability (CWE-347). This flaw allows a remote, unauthorized attacker to elevate their privileges over a network, potentially leading to full compromise of confidentiality, integrity, and availability.

Affected products:
- Microsoft 365 Admin Center

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-62873

## CVE-2026-62896

Microsoft Teams contains an improper authentication vulnerability that allows an authenticated attacker to perform privilege escalation over a network. This flaw represents a critical security risk due to the potential for unauthorized access elevation within the application environment.

Affected products:
- Microsoft Teams

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-62896

















Related in this roundup: [CVE-2026-65667](#cve-2026-65667), [CVE-2026-62918](#cve-2026-62918).

## CVE-2026-63508

Microsoft Planetary Computer Pro (GeoCatalog) contains a vulnerability due to missing authentication for a critical function. This allows an unauthorized attacker to perform privilege escalation over a network. The vulnerability is classified as critical and has a CVSS base score of 10.0.

Affected products:
- Microsoft Planetary Computer Pro (GeoCatalog)

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-63508

## CVE-2026-65667

CVE-2026-65667 is a critical security vulnerability in Microsoft Teams involving missing authorization (CWE-862). This flaw allows a remote, unauthenticated attacker to elevate privileges over a network, potentially leading to unauthorized access to sensitive information and system integrity compromises.

Affected products:
- Microsoft Teams

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-65667

















Related in this roundup: [CVE-2026-62896](#cve-2026-62896), [CVE-2026-62918](#cve-2026-62918).

## CVE-2026-68823

CVE-2026-68823 involves an exposed dangerous method or function in the Azure Confidential Ledger service, which allows an authorized attacker to achieve remote code execution over a network. The vulnerability is classified as CWE-749 and carries a critical CVSS base score of 9.1.

Affected products:
- Azure Confidential Ledger

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-68823

## CVE-2026-70332

CVE-2026-70332 is a Server-Side Request Forgery (SSRF) vulnerability in Microsoft SharePoint Online. An unauthenticated attacker can exploit this flaw to perform spoofing over a network, potentially leading to unauthorized information disclosure, interaction with internal services, or further lateral movement within the cloud environment.

Affected products:
- SharePoint Online

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-70332

## CVE-2026-49163

Application Insights Profiler is vulnerable to a path traversal flaw (CWE-22) that allows an authorized attacker to elevate their privileges over a network. This vulnerability indicates improper limitation of a pathname to a restricted directory.

Affected products:
- Application Insights Profiler

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-49163

## CVE-2026-62836

CVE-2026-62836 identifies a vulnerability in Azure SQL Managed Instance due to improper restriction of communication channels to intended endpoints. This flaw allows an unauthenticated, remote attacker to escalate privileges over a network connection by exploiting the misconfigured communication path.

Affected products:
- Azure SQL Managed Instance

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-62836

## CVE-2026-62918

CVE-2026-62918 is a vulnerability in Microsoft Teams involving improper verification of cryptographic signatures. This flaw allows an unauthorized remote attacker to perform spoofing attacks over a network, potentially leading to unauthorized data manipulation or masquerading within the platform.

Affected products:
- Microsoft Teams

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-62918

















Related in this roundup: [CVE-2026-62896](#cve-2026-62896), [CVE-2026-65667](#cve-2026-65667).

## CVE-2026-65668

Microsoft Purview eDiscovery contains an improper access control vulnerability that allows an authenticated attacker to perform a privilege escalation attack over the network. Detection should focus on monitoring unauthorized account role modifications or unexpected administrative actions within the Purview compliance console.

Affected products:
- Microsoft Purview eDiscovery

Source: https://nvd.nist.gov/vuln/detail/CVE-2026-65668

## CVE-2026-68480

CVE-2026-68480 relates to a vulnerability in the x86 Safe-RET implementation regarding interrupt injection, which could allow a local attacker to potentially bypass security protections or escalate privileges. Security updates for affected versions of the Windows operating system address the robustness of the return mechanism against these specific interrupt vectors.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68480

















Related in this roundup: [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-64564

CVE-2026-64564 involves a vulnerability in the SCTP (Stream Control Transmission Protocol) implementation within Microsoft Windows. The issue occurs during DEL-IP processing, where the ASCONF (Address Configuration Change Chunk) packet handling incorrectly attempts to free its own transport, potentially leading to a use-after-free or memory management error.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64564

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-64590

CVE-2026-64590 identifies an issue within the dma-buf/udmabuf component where a redundant CPU synchronization triggers a cacheline EEXIST warning. This update addresses the underlying logic to ensure proper synchronization handling.

Affected products:
- dma-buf/udmabuf

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64590

## CVE-2026-54876

CVE-2026-54876 describes a client-side memory leak vulnerability within the OCSP (Online Certificate Status Protocol) response checking mechanism in Microsoft Windows products.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-54876

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-44605

CVE-2026-44605 describes a heap-based buffer overflow vulnerability located in the ndb slot table parsing logic within Rpm. This vulnerability could potentially allow for arbitrary code execution or memory corruption when processing malformed slot tables.

Affected products:
- Rpm

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-44605

## CVE-2026-64573

A vulnerability identified in the Bluetooth NVM tag length TLV parser leads to an underflow condition. This security update from Microsoft addresses the flaw to prevent potential memory corruption or exploitation within the Bluetooth component.

Affected products:
- Bluetooth

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64573

## CVE-2026-64565

CVE-2026-64565 refers to a heap-based buffer overflow vulnerability located within the ims_pcu_process_data() function of the ims-pcu component, potentially allowing for memory corruption or arbitrary code execution.

Affected products:
- ims-pcu

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64565

## CVE-2026-64578

CVE-2026-64578 identifies a vulnerability in the ksmbd kernel-mode SMB server, where insufficient validation of compound request sizes before reading StructureSize2 can lead to memory safety issues. Detection engineering should focus on monitoring SMB traffic patterns for malformed or oversized requests that could trigger improper bounds handling.

Affected products:
- ksmbd

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64578

















Related in this roundup: [CVE-2026-68097](#cve-2026-68097), [CVE-2026-68130](#cve-2026-68130), [CVE-2026-68099](#cve-2026-68099), [CVE-2026-68098](#cve-2026-68098).

## CVE-2024-21380

CVE-2024-21380 is an information disclosure vulnerability affecting Microsoft Dynamics Business Central and Dynamics NAV. The disclosure indicates an informational update to build numbers provided by Microsoft in the Security Update Guide, with no functional changes described in the provided content.

Affected products:
- Dynamics Business Central
- Dynamics NAV

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21380

## CVE-2025-2308

CVE-2025-2308 is a heap-based buffer overflow vulnerability residing in the H5Z__scaleoffset_decompress_one_byte function within the HDF5 scale-offset filter, potentially allowing for arbitrary code execution if a maliciously crafted HDF5 file is processed.

Affected products:
- HDF5

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-2308

















Related in this roundup: [CVE-2025-2309](#cve-2025-2309).

## CVE-2025-2309

CVE-2025-2309 refers to a heap-based buffer overflow vulnerability identified in the HDF5 library specifically within the H5T__bit_copy type conversion logic. The vulnerability could potentially lead to memory corruption or arbitrary code execution if an attacker provides a maliciously crafted HDF5 file to an application utilizing the affected library code for data processing.

Affected products:
- HDF5

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-2309

















Related in this roundup: [CVE-2025-2308](#cve-2025-2308).

## CVE-2026-68097

CVE-2026-68097 identifies a vulnerability in ksmbd where the software fails to properly validate the size of an Access Control Entry (ACE) against the number of Security Identifier (SID) sub-authorities. This vulnerability could potentially lead to memory corruption or other instability issues when processing malicious SMB traffic.

Affected products:
- ksmbd

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68097

















Related in this roundup: [CVE-2026-64578](#cve-2026-64578), [CVE-2026-68130](#cve-2026-68130), [CVE-2026-68099](#cve-2026-68099), [CVE-2026-68098](#cve-2026-68098).

## CVE-2026-68388

CVE-2026-68388 addresses a vulnerability in the SMB client component of the Windows operating system related to the improper handling of overlapping allocated ranges during fallocate operations, which may lead to memory corruption or instability.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68388

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68187

CVE-2026-68187 describes an unsigned loop counter wrap vulnerability within the transfer_args_to_stack() function in Microsoft software, potentially allowing for memory corruption or unstable execution states.

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68187

## CVE-2026-68152

CVE-2026-68152 addresses a use-after-free vulnerability within the AMT delayed works component in Microsoft products, which could potentially lead to system instability or arbitrary code execution.

Affected products:
- AMT

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68152

## CVE-2026-68189

CVE-2026-68189 refers to a vulnerability within the Bluetooth hci_sync component in Microsoft Windows. The issue involves a lack of protection during UUID list traversal, which may lead to memory safety issues or instability during Bluetooth stack operations.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68189

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68312

CVE-2026-68312 describes a memory leak vulnerability in the CIFS (Common Internet File System) implementation within the Windows kernel. The issue specifically occurs in the deferred close drain paths when a kmalloc memory allocation fails, leading to a cifsFileInfo object leak, which could potentially be leveraged for denial-of-service conditions.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68312

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68130

CVE-2026-68130 identifies a security vulnerability in the ksmbd component within Microsoft Windows Server. The flaw involves the premature destruction of the previous session before NTLM authentication is fully completed, which could lead to authentication bypass or session handling errors. Security teams should ensure that the provided update is applied to affected server environments to enforce proper session lifecycle management during the authentication handshake.

Affected products:
- ksmbd

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68130

















Related in this roundup: [CVE-2026-64578](#cve-2026-64578), [CVE-2026-68097](#cve-2026-68097), [CVE-2026-68099](#cve-2026-68099), [CVE-2026-68098](#cve-2026-68098).

## CVE-2026-68176

CVE-2026-68176 describes a vulnerability in mmiotrace involving a potential NULL pointer dereferencing issue regarding the hiter->dev pointer. This flaw could lead to a system crash or unstable behavior when handled improperly during tracing operations.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68176

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68145

CVE-2026-68145 concerns an out-of-bounds vulnerability in the iomap component, specifically triggered during bitmap_set operations involving zero-length ranges. This flaw could potentially allow for memory corruption, impacting system stability or security.

Affected products:
- iomap

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68145

## CVE-2026-68318

CVE-2026-68318 is a vulnerability in pds_core involving a use-after-free condition triggered during the removal process of a workqueue. The issue arises due to improper memory management, which could potentially be exploited to cause a system crash or arbitrary code execution.

Affected products:
- pds_core

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68318

## CVE-2026-68118

CVE-2026-68118 describes a vulnerability in the TCP stack implementation where improper handling of challenge ACKs for non-exact RST packets in the SYN-RECEIVED state can be exploited to cause a denial-of-service condition or disrupt network connections.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68118

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68175

CVE-2026-68175 refers to a resource leak vulnerability identified within the mmiotrace trace_pipe close function in Microsoft Windows, which could potentially be leveraged for local denial-of-service conditions or resource exhaustion.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68175

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68328

CVE-2026-68328 identifies a vulnerability within the Windows nfp (Near-Field Proximity) driver related to resource mutex allocation, as reported by the Microsoft Security Response Center.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68328

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68406

CVE-2026-68406 identifies a vulnerability in the wifi cfg80211 subsystem where the PMSR FTM preamble range is improperly validated. This flaw can potentially lead to memory corruption or instability within the wireless driver stack, necessitating a security update to ensure proper bounds checking for wireless frame parameters.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68406

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68317

CVE-2026-68317 refers to a vulnerability in pds_core involving race conditions during auxiliary device addition or deletion. The issue requires patching to ensure stability and prevent potential exploitation via race conditions.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68317

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68099

CVE-2026-68099 is a vulnerability in the ksmbd component within Microsoft Windows, where an integer overflow check in check_add_overflow() fails to correctly restore DACL size, potentially leading to the processing of malformed ACLs. This flaw could be exploited to cause memory corruption or denial of service conditions by submitting specially crafted SMB packets.

Affected products:
- ksmbd

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68099

















Related in this roundup: [CVE-2026-64578](#cve-2026-64578), [CVE-2026-68097](#cve-2026-68097), [CVE-2026-68130](#cve-2026-68130), [CVE-2026-68098](#cve-2026-68098).

## CVE-2026-68354

CVE-2026-68354 refers to a vulnerability within the Windows firewire network driver stack involving improper handling of fragmented datagram reassembly, which may allow for potential exploitation during network packet processing.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68354

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68326

CVE-2026-68326 is a vulnerability within the mwifiex Wi-Fi driver, specifically involving improper bounds checking of uAP association event Information Elements (IEs) against the event buffer. This flaw could potentially allow for memory corruption or other impacts depending on how the driver processes malformed association packets.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68326

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68151

CVE-2026-68151 identifies a vulnerability within the binfmt_elf_fdpic loader, which incorrectly handles multiple PT_INTERP segments in an ELF file. By only honoring the first PT_INTERP, the implementation may lead to inconsistencies in how executable files are parsed and executed, potentially impacting system security and loader integrity.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68151

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68343

CVE-2026-68343 describes a vulnerability in the Microsoft SMB client related to the validation of DFS referral PathConsumed. This flaw potentially allows an attacker to manipulate path validation logic within SMB communications.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68343

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68184

CVE-2026-68184 describes a stack-based out-of-bounds read vulnerability within the CDROMVOLCTRL functionality of the Windows CD-ROM driver. This flaw could potentially be leveraged by an attacker to read sensitive data from the stack, though specific exploitation vectors are not detailed beyond the vulnerability type.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68184

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68124

CVE-2026-68124 identifies a buffer overflow vulnerability within the MCTP serial driver components, triggered by the improper handling of zero-length frames. An attacker could potentially exploit this flaw to cause memory corruption or a system crash.

Affected products:
- mctp

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68124

## CVE-2026-68401

CVE-2026-68401 describes an out-of-bounds write vulnerability within the arm_ffa component of Microsoft firmware, specifically located in the ffa_setup_and_transmit() function, which requires a security update to remediate.

Affected products:
- firmware

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68401

## CVE-2026-68322

CVE-2026-68322 describes a NULL pointer dereference vulnerability within the rds (Reliable Datagram Sockets) component of Microsoft Windows, specifically occurring when IPv6 is disabled. This vulnerability can lead to a system crash, resulting in a denial of service condition.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68322

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68214

CVE-2026-68214 identifies a use-after-free vulnerability located in the rtl2832 driver's remove function (rtl2832_remove) within the Windows kernel. This flaw could potentially be leveraged to trigger system instability or lead to memory corruption, requiring a kernel-level security update to address the lifetime management of the driver object.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68214

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68327

CVE-2026-68327 is a vulnerability identified in the Microsoft wanxl WAN driver component. The vulnerability relates to the handling of hardware reset sequences in relation to Base Address Register (BAR) mapping. Successful exploitation of this issue could potentially lead to undefined system behavior or stability issues within the network driver stack.

Affected products:
- wanxl

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68327

## CVE-2026-68188

CVE-2026-68188 describes a use-after-free (UAF) vulnerability within the RFCOMM protocol implementation of the Bluetooth stack, specifically triggered during the set_termios operation.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68188

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68132

CVE-2026-68132 is a vulnerability addressed by Microsoft that involves a deadlock condition occurring during the emergency thaw process on frozen block devices within the Windows operating system.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68132

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68304

CVE-2026-68304 addresses a call trace warning in the brcmfmac wireless driver related to 802.1X-SHA256 authentication processing. While technical details are limited, the issue involves handling of authentication frames within the Broadcom wireless stack.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68304

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68098

CVE-2026-68098 is a vulnerability in the ksmbd kernel-mode SMB server component within Microsoft Windows. The issue involves improper handling of DACL (Discretionary Access Control List) deduplication during ACE (Access Control Entry) copying operations, which may lead to memory safety issues when processing malformed requests.

Affected products:
- ksmbd

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68098

















Related in this roundup: [CVE-2026-64578](#cve-2026-64578), [CVE-2026-68097](#cve-2026-68097), [CVE-2026-68130](#cve-2026-68130), [CVE-2026-68099](#cve-2026-68099).

## CVE-2026-68348

CVE-2026-68348 involves an issue in the ASoC (ALSA System on Chip) subsystem specifically related to the tas2781 audio amplifier driver, where firmware description string parsing is not properly bounded, potentially leading to memory corruption or related stability issues.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68348

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68195

CVE-2026-68195 describes a vulnerability in the mt76 driver for MediaTek WiFi chipsets, specifically affecting the mt7615 module. The vulnerability involves improper handling of TXRX_NOTIFY events on non-MMIO buses, requiring a patch to drop these notifications to maintain stability and security.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68195

















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68419

CVE-2026-68419 is a vulnerability in the Linux kernel's irdma (RDMA) subsystem. The flaw specifically pertains to the rereg_mr function, which fails to properly validate that the memory region being re-registered is a valid memory region, potentially leading to unauthorized memory access or system instability.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68419
















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68171

CVE-2026-68171 refers to a vulnerability in the Linux kernel for the arm64 architecture, specifically related to syscall handling. The flaw involves a synchronization issue where the saved x0 register may not correctly reflect updates made by a tracer during a system call, potentially leading to security boundary bypasses or incorrect syscall execution context.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68171















Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-64523

CVE-2026-64523 is a vulnerability in the Microsoft net/handshake component involving the handling of long-lived file references during submission processes, which has been identified and addressed by Microsoft via the Security Update Guide.

Affected products:
- net/handshake

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64523

## CVE-2026-64388

CVE-2026-64388 refers to a security update for the Microsoft SMB client component, specifically addressing improper handling of POSIX chown/chgrp operations when using SMB3 POSIX Extensions.

Affected products:
- SMB Client

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64388

## CVE-2025-37938

CVE-2025-37938 refers to a security vulnerability related to the tracing of event formats containing '%*p' sequences. The provided content is a placeholder index for a Microsoft Security Response Center advisory, and specific technical details regarding the vulnerability's impact, affected products, or exploitation vectors are not currently available within the source text.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-37938












Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2026-68207](#cve-2026-68207), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-68207

CVE-2026-68207 involves an error in the Video4Linux2 (v4l2) device registration process within the Linux kernel, specifically related to improper cleanup during probe errors. This flaw could potentially lead to inconsistent system states or kernel-level instability upon initialization failure.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68207











Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-50472](#cve-2026-50472).

## CVE-2026-50472

A heap-based buffer overflow vulnerability in the Windows LUA File Virtualization (LUAFV) filter driver allows a locally authenticated attacker to escalate privileges to the level of the kernel or system.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-50472










Related in this roundup: [CVE-2026-68480](#cve-2026-68480), [CVE-2026-64564](#cve-2026-64564), [CVE-2026-54876](#cve-2026-54876), [CVE-2026-68388](#cve-2026-68388), [CVE-2026-68189](#cve-2026-68189), [CVE-2026-68312](#cve-2026-68312), [CVE-2026-68176](#cve-2026-68176), [CVE-2026-68118](#cve-2026-68118), [CVE-2026-68175](#cve-2026-68175), [CVE-2026-68328](#cve-2026-68328), [CVE-2026-68406](#cve-2026-68406), [CVE-2026-68317](#cve-2026-68317), [CVE-2026-68354](#cve-2026-68354), [CVE-2026-68326](#cve-2026-68326), [CVE-2026-68151](#cve-2026-68151), [CVE-2026-68343](#cve-2026-68343), [CVE-2026-68184](#cve-2026-68184), [CVE-2026-68322](#cve-2026-68322), [CVE-2026-68214](#cve-2026-68214), [CVE-2026-68188](#cve-2026-68188), [CVE-2026-68132](#cve-2026-68132), [CVE-2026-68304](#cve-2026-68304), [CVE-2026-68348](#cve-2026-68348), [CVE-2026-68195](#cve-2026-68195), [CVE-2026-68419](#cve-2026-68419), [CVE-2026-68171](#cve-2026-68171), [CVE-2025-37938](#cve-2025-37938), [CVE-2026-68207](#cve-2026-68207).

## CVE-2026-56174

CVE-2026-56174 describes an elevation of privilege vulnerability in Windows Narrator Braille caused by an untrusted search path. An attacker with local access can exploit this vulnerability to execute code or perform operations with higher privileges than their account typically permits.

Affected products:
- Windows Narrator

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-56174

## CVE-2026-58650

CVE-2026-58650 describes an authorization bypass vulnerability in Visual Studio Code where a user-controlled key can be leveraged to bypass security features locally. An unauthorized attacker requires local access to exploit this flaw, which stems from improper handling of authorization keys.

Affected products:
- Visual Studio Code

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58650

## CVE-2026-65768

Microsoft Teams for Android contains a path traversal vulnerability that allows a remote, unauthorized attacker to execute arbitrary code on the target device via network-based exploitation.

Affected products:
- Teams

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-65768

## CVE-2026-57105

CVE-2026-57105 is a spoofing vulnerability in Microsoft Office SharePoint caused by improper neutralization of input during web page generation. An authenticated attacker can exploit this cross-site scripting vulnerability to conduct spoofing attacks over the network.

Affected products:
- SharePoint

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-57105

## CVE-2026-62829

CVE-2026-62829 is a cross-site scripting (XSS) vulnerability in Microsoft SharePoint Server that allows an authenticated attacker to perform spoofing attacks over a network by injecting malicious input during web page generation.

Affected products:
- SharePoint Server

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62829




Related in this roundup: [CVE-2026-62827](#cve-2026-62827), [CVE-2026-62837](#cve-2026-62837), [CVE-2026-63514](#cve-2026-63514), [CVE-2026-63512](#cve-2026-63512).

## CVE-2026-62827

CVE-2026-62827 is an elevation of privilege vulnerability in Microsoft SharePoint Server caused by improper authentication, allowing an authenticated attacker to elevate their privileges over a network.

Affected products:
- SharePoint Server

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62827




Related in this roundup: [CVE-2026-62829](#cve-2026-62829), [CVE-2026-62837](#cve-2026-62837), [CVE-2026-63514](#cve-2026-63514), [CVE-2026-63512](#cve-2026-63512).

## CVE-2026-62837

CVE-2026-62837 describes a relative path traversal vulnerability in Microsoft SharePoint Server that allows an authenticated attacker to perform unauthorized information disclosure over the network.

Affected products:
- SharePoint Server

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62837



Related in this roundup: [CVE-2026-62829](#cve-2026-62829), [CVE-2026-62827](#cve-2026-62827), [CVE-2026-63514](#cve-2026-63514), [CVE-2026-63512](#cve-2026-63512).

## CVE-2026-63514

CVE-2026-63514 is a remote code execution vulnerability in Microsoft SharePoint Server caused by improper deserialization of untrusted data. An authorized attacker can exploit this flaw over the network to execute arbitrary code within the context of the application.

Affected products:
- SharePoint Server

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-63514


Related in this roundup: [CVE-2026-62829](#cve-2026-62829), [CVE-2026-62827](#cve-2026-62827), [CVE-2026-62837](#cve-2026-62837), [CVE-2026-63512](#cve-2026-63512).

## CVE-2026-63512

CVE-2026-63512 is a security vulnerability in Microsoft SharePoint Server that results from incorrect authorization handling. An attacker who has obtained authorized access to the system can exploit this flaw to perform unauthorized tampering with data or configuration over a network, potentially undermining system integrity.

Affected products:
- SharePoint Server

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-63512

Related in this roundup: [CVE-2026-62829](#cve-2026-62829), [CVE-2026-62827](#cve-2026-62827), [CVE-2026-62837](#cve-2026-62837), [CVE-2026-63514](#cve-2026-63514).
