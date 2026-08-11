---
title: Microsoft Security Updates — August 2026
slug: 2026-08-microsoft-security-updates
description: Roundup of Microsoft security advisories published in August 2026.
date: "2026-08-01T01:41:40Z"
lastmod: "2026-08-11T09:52:12Z"
type: threat
types:
  - threat
severities:
  - high
cpes:
  - cpe:2.3:a:microsoft:azure_active_directory:-:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:azure_service_bus:-:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:entra_provisioning_service:-:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:power_apps:-:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:azure_sre_agent:-:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:teams:-:*:*:*:*:*:*:*
tags:
  - roundup
vendors:
  - Microsoft
cves:
  - id: CVE-2026-50481
    cvss: 9.9
    epss: 0.00456
  - id: CVE-2026-50515
    cvss: 9.9
    epss: 0.0091
  - id: CVE-2026-59115
    cvss: 9.9
    epss: 0.00635
  - id: CVE-2026-59118
    cvss: 9.3
    epss: 0.0039
  - id: CVE-2026-62830
    cvss: 9.9
    epss: 0.00417
  - id: CVE-2026-62896
    cvss: 9.6
    epss: 0.00381
  - id: CVE-2026-44605
    cvss: 5.5
    epss: 0.00135
  - id: CVE-2026-64578
    cvss: 8.2
    epss: 0.00317
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68097
updates:
  - at: "2026-08-09T09:38:22Z"
    level: L1
    summary: new product
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64578
  - at: "2026-08-10T19:33:14Z"
    level: L2
    summary: added CVE-2026-62918 +1
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21380
  - at: "2026-08-11T09:51:12Z"
    level: L2
    summary: added CVE-2026-50481 +3
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-2308
  - at: "2026-08-11T09:51:17Z"
    level: L2
    summary: added CVE-2026-44605 +1
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-2309
  - at: "2026-08-11T09:52:12Z"
    level: L2
    summary: added CVE-2026-64578
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68097
---

This roundup covers 27 Microsoft security vulnerabilities. None are reported as actively exploited at the time of release. The issues affect Application Insights Profiler, Azure Active Directory, Azure Confidential Ledger, Azure Logic Apps, Azure SQL Managed Instance, Azure SRE Agent, Azure Service Bus, Bluetooth, Dynamics Business Central, HDF5, Microsoft 365 Admin Center, Microsoft Entra Provisioning Service, Microsoft Planetary Computer Pro, Microsoft Purview eDiscovery, Microsoft Teams, Power Apps, Rpm, SharePoint Online, Windows, dma-buf/udmabuf, ims-pcu, ksmbd.

## Summary

| CVE | CVSS | Product | Summary |
|-----|------|---------|---------|
| CVE-2026-50481 | 9.9 | Azure Active Directory | CVE-2026-50481 is a critical vulnerability in Microsoft Azure Active Directory involving the modification of assumed-immutable data (MAID). An authorized attacker can exploit this flaw to escalate privileges within the environment over a network, potentially leading to unauthorized administrative access. |
| CVE-2026-50515 | 9.9 | Azure Service Bus | CVE-2026-50515 is a critical deserialization of untrusted data vulnerability in Azure Service Bus that permits an authenticated attacker with low privileges to achieve remote code execution. Detection efforts should focus on monitoring anomalous serialized data payloads sent to service bus endpoints and unexpected process execution spawned by the Azure Service Bus service account. |
| CVE-2026-56161 | 0.0 | Azure Logic Apps | CVE-2026-56161 describes an improper access control vulnerability in Microsoft Azure Logic Apps. An authenticated attacker can exploit this vulnerability to disclose sensitive information over a network. The vulnerability carries a CVSS 3.1 base score of 9.6, indicating a critical risk. |
| CVE-2026-59115 | 9.9 | Microsoft Entra Provisioning Service | CVE-2026-59115 is a critical path traversal vulnerability in the Microsoft Entra Provisioning Service (SyncFabric). An authorized attacker can leverage this vulnerability by using a specific input string ('.../...//') to elevate their privileges over a network. The vulnerability has a CVSS base score of 9.9, indicating a significant risk to the integrity, confidentiality, and availability of the affected cloud service. |
| CVE-2026-59118 | 9.3 | Power Apps | CVE-2026-59118 is an improper authorization vulnerability in Microsoft Power Apps that allows an unauthorized attacker to perform a privilege escalation over a network. The vulnerability carries a CVSS 3.1 base score of 9.3, indicating a critical severity impact on confidentiality and integrity, necessitating restricted access controls within the affected cloud service. |
| CVE-2026-62830 | 9.9 | Azure SRE Agent | A vulnerability in the Azure SRE Agent stemming from missing authorization (CWE-862) allows an already authorized network attacker to perform privilege escalation. The vulnerability is rated critical with a CVSS 3.1 score of 9.9, as it enables full scope impact across confidentiality, integrity, and availability within the cloud environment. |
| CVE-2026-62873 | 0.0 | Microsoft 365 Admin Center | The Microsoft 365 Admin Center is vulnerable to an improper verification of cryptographic signature vulnerability (CWE-347). This flaw allows a remote, unauthorized attacker to elevate their privileges over a network, potentially leading to full compromise of confidentiality, integrity, and availability. |
| CVE-2026-62896 | 9.6 | Microsoft Teams | Microsoft Teams contains an improper authentication vulnerability that allows an authenticated attacker to perform privilege escalation over a network. This flaw represents a critical security risk due to the potential for unauthorized access elevation within the application environment. |
| CVE-2026-63508 | 0.0 | Microsoft Planetary Computer Pro (GeoCatalog) | Microsoft Planetary Computer Pro (GeoCatalog) contains a vulnerability due to missing authentication for a critical function. This allows an unauthorized attacker to perform privilege escalation over a network. The vulnerability is classified as critical and has a CVSS base score of 10.0. |
| CVE-2026-65667 | 0.0 | Microsoft Teams | CVE-2026-65667 is a critical security vulnerability in Microsoft Teams involving missing authorization (CWE-862). This flaw allows a remote, unauthenticated attacker to elevate privileges over a network, potentially leading to unauthorized access to sensitive information and system integrity compromises. |
| CVE-2026-68823 | 0.0 | Azure Confidential Ledger | CVE-2026-68823 involves an exposed dangerous method or function in the Azure Confidential Ledger service, which allows an authorized attacker to achieve remote code execution over a network. The vulnerability is classified as CWE-749 and carries a critical CVSS base score of 9.1. |
| CVE-2026-70332 | 0.0 | SharePoint Online | CVE-2026-70332 is a Server-Side Request Forgery (SSRF) vulnerability in Microsoft SharePoint Online. An unauthenticated attacker can exploit this flaw to perform spoofing over a network, potentially leading to unauthorized information disclosure, interaction with internal services, or further lateral movement within the cloud environment. |
| CVE-2026-49163 | 0.0 | Application Insights Profiler | Application Insights Profiler is vulnerable to a path traversal flaw (CWE-22) that allows an authorized attacker to elevate their privileges over a network. This vulnerability indicates improper limitation of a pathname to a restricted directory. |
| CVE-2026-62836 | 0.0 | Azure SQL Managed Instance | CVE-2026-62836 identifies a vulnerability in Azure SQL Managed Instance due to improper restriction of communication channels to intended endpoints. This flaw allows an unauthenticated, remote attacker to escalate privileges over a network connection by exploiting the misconfigured communication path. |
| CVE-2026-62918 | 0.0 | Microsoft Teams | CVE-2026-62918 is a vulnerability in Microsoft Teams involving improper verification of cryptographic signatures. This flaw allows an unauthorized remote attacker to perform spoofing attacks over a network, potentially leading to unauthorized data manipulation or masquerading within the platform. |
| CVE-2026-65668 | 0.0 | Microsoft Purview eDiscovery | Microsoft Purview eDiscovery contains an improper access control vulnerability that allows an authenticated attacker to perform a privilege escalation attack over the network. Detection should focus on monitoring unauthorized account role modifications or unexpected administrative actions within the Purview compliance console. |
| CVE-2026-68480 | 0.0 | Windows | CVE-2026-68480 relates to a vulnerability in the x86 Safe-RET implementation regarding interrupt injection, which could allow a local attacker to potentially bypass security protections or escalate privileges. Security updates for affected versions of the Windows operating system address the robustness of the return mechanism against these specific interrupt vectors. |
| CVE-2026-64564 | 0.0 | Windows | CVE-2026-64564 involves a vulnerability in the SCTP (Stream Control Transmission Protocol) implementation within Microsoft Windows. The issue occurs during DEL-IP processing, where the ASCONF (Address Configuration Change Chunk) packet handling incorrectly attempts to free its own transport, potentially leading to a use-after-free or memory management error. |
| CVE-2026-64590 | 0.0 | dma-buf/udmabuf | CVE-2026-64590 identifies an issue within the dma-buf/udmabuf component where a redundant CPU synchronization triggers a cacheline EEXIST warning. This update addresses the underlying logic to ensure proper synchronization handling. |
| CVE-2026-54876 | 0.0 | Windows | CVE-2026-54876 describes a client-side memory leak vulnerability within the OCSP (Online Certificate Status Protocol) response checking mechanism in Microsoft Windows products. |
| CVE-2026-44605 | 5.5 | Rpm | CVE-2026-44605 describes a heap-based buffer overflow vulnerability located in the ndb slot table parsing logic within Rpm. This vulnerability could potentially allow for arbitrary code execution or memory corruption when processing malformed slot tables. |
| CVE-2026-64573 | 0.0 | Bluetooth | A vulnerability identified in the Bluetooth NVM tag length TLV parser leads to an underflow condition. This security update from Microsoft addresses the flaw to prevent potential memory corruption or exploitation within the Bluetooth component. |
| CVE-2026-64565 | 0.0 | ims-pcu | CVE-2026-64565 refers to a heap-based buffer overflow vulnerability located within the ims_pcu_process_data() function of the ims-pcu component, potentially allowing for memory corruption or arbitrary code execution. |
| CVE-2026-64578 | 0.0 | ksmbd | CVE-2026-64578 identifies a vulnerability in the ksmbd kernel-mode SMB server, where insufficient validation of compound request sizes before reading StructureSize2 can lead to memory safety issues. Detection engineering should focus on monitoring SMB traffic patterns for malformed or oversized requests that could trigger improper bounds handling. |
| CVE-2024-21380 | 0.0 | Dynamics Business Central | CVE-2024-21380 is an information disclosure vulnerability affecting Microsoft Dynamics Business Central and Dynamics NAV. The disclosure indicates an informational update to build numbers provided by Microsoft in the Security Update Guide, with no functional changes described in the provided content. |
| CVE-2025-2308 | 0.0 | HDF5 | CVE-2025-2308 is a heap-based buffer overflow vulnerability residing in the H5Z__scaleoffset_decompress_one_byte function within the HDF5 scale-offset filter, potentially allowing for arbitrary code execution if a maliciously crafted HDF5 file is processed. |
| CVE-2025-2309 | 0.0 | HDF5 | CVE-2025-2309 refers to a heap-based buffer overflow vulnerability identified in the HDF5 library specifically within the H5T__bit_copy type conversion logic. The vulnerability could potentially lead to memory corruption or arbitrary code execution if an attacker provides a maliciously crafted HDF5 file to an application utilizing the affected library code for data processing. |


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

## CVE-2026-64564

CVE-2026-64564 involves a vulnerability in the SCTP (Stream Control Transmission Protocol) implementation within Microsoft Windows. The issue occurs during DEL-IP processing, where the ASCONF (Address Configuration Change Chunk) packet handling incorrectly attempts to free its own transport, potentially leading to a use-after-free or memory management error.

Affected products:
- Windows

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64564

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

## CVE-2025-2309

CVE-2025-2309 refers to a heap-based buffer overflow vulnerability identified in the HDF5 library specifically within the H5T__bit_copy type conversion logic. The vulnerability could potentially lead to memory corruption or arbitrary code execution if an attacker provides a maliciously crafted HDF5 file to an application utilizing the affected library code for data processing.

Affected products:
- HDF5

Source: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-2309
