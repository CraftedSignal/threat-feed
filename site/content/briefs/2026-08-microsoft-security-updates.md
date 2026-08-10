---
title: Microsoft Security Updates — August 2026
slug: 2026-08-microsoft-security-updates
description: Roundup of Microsoft security advisories published in August 2026.
date: "2026-08-01T01:41:40Z"
lastmod: "2026-08-10T19:33:14Z"
type: threat
types:
  - threat
severities:
  - high
cpes:
  - cpe:2.3:a:microsoft:power_apps:-:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:teams:-:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=C70098EC-8455-5303-80B5-BD82E10260AE&utm_source=rss&utm_medium=rss
tags:
  - roundup
vendors:
  - Microsoft
  - Elastic
  - Google
  - GitHub
  - Roblox
  - Discord
  - Mojang
products:
  - Windows
  - Microsoft Entra ID
  - curl
  - Azure Kubernetes Service
  - Azure Storage
  - GitHub
  - Elastic Stack
  - Azure Kubernetes Service (AKS)
  - Microsoft 365
  - SOHO routers
  - Azure Cosmos DB
  - Android
  - Windows Subsystem for Linux
  - PowerShell
  - Microsoft 365 Apps for Enterprise
  - Microsoft Excel 2016 (< 16.0.5561.1001)
  - Microsoft Office 2019
  - Microsoft Office LTSC 2021
  - Microsoft Office LTSC 2024
  - Roblox
  - Discord
  - Minecraft
  - Xbox Game Bar
  - .NET Framework (<= 4.8.1)
  - .NET Runtime (8.0.0 - 8.0.28, 9.0.0 - 9.0.17, 10.0.0 - 10.0.9)
  - Visual Studio 2022 (<= 17.14)
  - Visual Studio 2026 (<= 18.7)
  - Microsoft Edge (Android) (< 151.0.4129.59)
  - Microsoft Edge for Android (< 151.0.4129.59)
  - Microsoft Edge (Chromium-based) (< 151.0.4129.59)
  - Edge
  - Excel 2016
  - Office 2019
  - Office 2021
  - Office 2024
  - Microsoft 365 Apps Enterprise
  - SharePoint Server
  - Internet Information Services
  - Azure Active Directory
  - Azure Service Bus
  - Azure Logic Apps
  - Microsoft Entra Provisioning Service
  - Power Apps
  - Azure SRE Agent
  - Microsoft 365 Admin Center
  - Microsoft Teams
  - Microsoft Planetary Computer Pro (GeoCatalog)
  - Azure Confidential Ledger
  - SharePoint Online
  - Application Insights Profiler
  - Azure SQL Managed Instance
  - Microsoft Purview eDiscovery
  - dma-buf/udmabuf
  - Rpm
  - Bluetooth
  - ims-pcu
  - ksmbd
  - Dynamics Business Central
  - Dynamics NAV
affected_os:
  - Windows
  - Android
  - Alpine Linux
cves:
  - id: CVE-2026-59118
    cvss: 9.3
    epss: 0.0039
  - id: CVE-2026-65667
    cvss: 10
    epss: 0.00442
  - id: CVE-2026-62918
    cvss: 7.5
    epss: 0.00293
  - id: CVE-2026-64564
    cvss: 9.8
    epss: 0.00476
  - id: CVE-2026-64573
    epss: 0.00156
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_mark_of_the_web_removal_unusual_process.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/initial_access_entra_id_rare_app_id_for_principal_auth.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/command_and_control_curl_activity_llm_triage.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/command_and_control_wget_activity_llm_triage.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/credential_access_azure_aks_coredns_configmap_modified.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/credential_access_azure_aks_secret_access_suspicious_user_agent.toml
  - https://www.securityweek.com/russian-state-apt-linked-to-recent-public-wi-fi-gateway-hacking/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_service_windows_service_winlog.toml
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2617
  - https://therecord.media/russian-wifi-hackers-hotels
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_wsl_bash_exec.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_windows_powershell_susp_args.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/lateral_movement_executable_tool_transfer_smb.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_local_scheduled_task_creation.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_suspicious_com_hijack_registry.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/credential_access_azure_aks_csr_created_or_approved.toml
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0961/
  - https://www.bitdefender.com/en-us/blog/labs/fake-xeno-roblox-discord-executor
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/credential_access_azure_aks_service_account_token_requested.toml
  - https://sploitus.com/exploit?id=C70098EC-8455-5303-80B5-BD82E10260AE&utm_source=rss&utm_medium=rss
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65802
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66310
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66315
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66318
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66321
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66322
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2643
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2625
  - https://therecord.media/swiss-bit-foitt-hacked-possibly-sharepoint-vulnerabilities
  - https://nvd.nist.gov/vuln/detail/CVE-2026-50481
  - https://nvd.nist.gov/vuln/detail/CVE-2026-50515
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56161
  - https://nvd.nist.gov/vuln/detail/CVE-2026-59115
  - https://nvd.nist.gov/vuln/detail/CVE-2026-59118
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62830
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62873
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62896
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63508
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65667
  - https://nvd.nist.gov/vuln/detail/CVE-2026-68823
  - https://nvd.nist.gov/vuln/detail/CVE-2026-70332
  - https://nvd.nist.gov/vuln/detail/CVE-2026-49163
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62836
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62918
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65668
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68480
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64564
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64590
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-54876
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-44605
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64573
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64565
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64578
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21380
iocs:
  - type: domain
    value: mcr.microsoft.com
  - type: domain
    value: acs-mirror.azureedge.net
  - type: domain
    value: packages.aks.azure.com
  - type: domain
    value: packages.microsoft.com
  - type: domain
    value: login.microsoftonline.com
  - type: domain
    value: management.azure.com
  - type: domain
    value: storage.googleapis.com
  - type: domain
    value: api.github.com
  - type: domain
    value: artifacts.elastic.co
  - type: domain
    value: download.elastic.co
  - type: ip
    value: 169.254.169.254
  - type: ip
    value: 168.63.129.16
  - type: url
    value: https://solthere.net/justacoolkat10
  - type: url
    value: https://solthere.net/api/v1/redeem
  - type: domain
    value: ipapi.co
  - type: domain
    value: ipwho.is
ioc_counts:
  domain: 12
  ip: 2
  url: 2
updates:
  - at: "2026-08-09T09:38:04Z"
    level: L2
    summary: added CVE-2026-62836 +2
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-44605
  - at: "2026-08-09T09:38:12Z"
    level: L2
    summary: added CVE-2026-54876 +1
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64573
  - at: "2026-08-09T09:38:14Z"
    level: L1
    summary: new product
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64565
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
---

This roundup covers 24 Microsoft security vulnerabilities. None are reported as actively exploited at the time of release. The issues affect Application Insights Profiler, Azure Active Directory, Azure Confidential Ledger, Azure Logic Apps, Azure SQL Managed Instance, Azure SRE Agent, Azure Service Bus, Bluetooth, Microsoft 365 Admin Center, Microsoft Entra Provisioning Service, Microsoft Planetary Computer Pro, Microsoft Purview eDiscovery, Microsoft Teams, Power Apps, Rpm, SharePoint Online, Windows, dma-buf/udmabuf, ims-pcu, ksmbd.

## Summary

| CVE | CVSS | Product | Summary |
|-----|------|---------|---------|
| CVE-2026-50481 | 9.9 | Azure Active Directory | CVE-2026-50481 is a critical vulnerability in Microsoft Azure Active Directory involving the modification of assumed-immutable data (MAID). An authorized attacker can exploit this flaw to escalate privileges within the environment over a network, potentially leading to unauthorized administrative access. |
| CVE-2026-50515 | 9.9 | Azure Service Bus | CVE-2026-50515 is a critical deserialization of untrusted data vulnerability in Azure Service Bus that permits an authenticated attacker with low privileges to achieve remote code execution. Detection efforts should focus on monitoring anomalous serialized data payloads sent to service bus endpoints and unexpected process execution spawned by the Azure Service Bus service account. |
| CVE-2026-56161 | 9.6 | Azure Logic Apps | CVE-2026-56161 describes an improper access control vulnerability in Microsoft Azure Logic Apps. An authenticated attacker can exploit this vulnerability to disclose sensitive information over a network. The vulnerability carries a CVSS 3.1 base score of 9.6, indicating a critical risk. |
| CVE-2026-59115 | 0.0 | Microsoft Entra Provisioning Service | CVE-2026-59115 is a critical path traversal vulnerability in the Microsoft Entra Provisioning Service (SyncFabric). An authorized attacker can leverage this vulnerability by using a specific input string ('.../...//') to elevate their privileges over a network. The vulnerability has a CVSS base score of 9.9, indicating a significant risk to the integrity, confidentiality, and availability of the affected cloud service. |
| CVE-2026-59118 | 9.3 | Power Apps | CVE-2026-59118 is an improper authorization vulnerability in Microsoft Power Apps that allows an unauthorized attacker to perform a privilege escalation over a network. The vulnerability carries a CVSS 3.1 base score of 9.3, indicating a critical severity impact on confidentiality and integrity, necessitating restricted access controls within the affected cloud service. |
| CVE-2026-62830 | 9.9 | Azure SRE Agent | A vulnerability in the Azure SRE Agent stemming from missing authorization (CWE-862) allows an already authorized network attacker to perform privilege escalation. The vulnerability is rated critical with a CVSS 3.1 score of 9.9, as it enables full scope impact across confidentiality, integrity, and availability within the cloud environment. |
| CVE-2026-62873 | 9.8 | Microsoft 365 Admin Center | The Microsoft 365 Admin Center is vulnerable to an improper verification of cryptographic signature vulnerability (CWE-347). This flaw allows a remote, unauthorized attacker to elevate their privileges over a network, potentially leading to full compromise of confidentiality, integrity, and availability. |
| CVE-2026-62896 | 9.6 | Microsoft Teams | Microsoft Teams contains an improper authentication vulnerability that allows an authenticated attacker to perform privilege escalation over a network. This flaw represents a critical security risk due to the potential for unauthorized access elevation within the application environment. |
| CVE-2026-63508 | 10.0 | Microsoft Planetary Computer Pro (GeoCatalog) | Microsoft Planetary Computer Pro (GeoCatalog) contains a vulnerability due to missing authentication for a critical function. This allows an unauthorized attacker to perform privilege escalation over a network. The vulnerability is classified as critical and has a CVSS base score of 10.0. |
| CVE-2026-65667 | 10.0 | Microsoft Teams | CVE-2026-65667 is a critical security vulnerability in Microsoft Teams involving missing authorization (CWE-862). This flaw allows a remote, unauthenticated attacker to elevate privileges over a network, potentially leading to unauthorized access to sensitive information and system integrity compromises. |
| CVE-2026-68823 | 9.1 | Azure Confidential Ledger | CVE-2026-68823 involves an exposed dangerous method or function in the Azure Confidential Ledger service, which allows an authorized attacker to achieve remote code execution over a network. The vulnerability is classified as CWE-749 and carries a critical CVSS base score of 9.1. |
| CVE-2026-70332 | 9.6 | SharePoint Online | CVE-2026-70332 is a Server-Side Request Forgery (SSRF) vulnerability in Microsoft SharePoint Online. An unauthenticated attacker can exploit this flaw to perform spoofing over a network, potentially leading to unauthorized information disclosure, interaction with internal services, or further lateral movement within the cloud environment. |
| CVE-2026-49163 | 8.8 | Application Insights Profiler | Application Insights Profiler is vulnerable to a path traversal flaw (CWE-22) that allows an authorized attacker to elevate their privileges over a network. This vulnerability indicates improper limitation of a pathname to a restricted directory. |
| CVE-2026-62836 | 8.7 | Azure SQL Managed Instance | CVE-2026-62836 identifies a vulnerability in Azure SQL Managed Instance due to improper restriction of communication channels to intended endpoints. This flaw allows an unauthenticated, remote attacker to escalate privileges over a network connection by exploiting the misconfigured communication path. |
| CVE-2026-62918 | 0.0 | Microsoft Teams | CVE-2026-62918 is a vulnerability in Microsoft Teams involving improper verification of cryptographic signatures. This flaw allows an unauthorized remote attacker to perform spoofing attacks over a network, potentially leading to unauthorized data manipulation or masquerading within the platform. |
| CVE-2026-65668 | 0.0 | Microsoft Purview eDiscovery | Microsoft Purview eDiscovery contains an improper access control vulnerability that allows an authenticated attacker to perform a privilege escalation attack over the network. Detection should focus on monitoring unauthorized account role modifications or unexpected administrative actions within the Purview compliance console. |
| CVE-2026-68480 | 0.0 | Windows | CVE-2026-68480 relates to a vulnerability in the x86 Safe-RET implementation regarding interrupt injection, which could allow a local attacker to potentially bypass security protections or escalate privileges. Security updates for affected versions of the Windows operating system address the robustness of the return mechanism against these specific interrupt vectors. |
| CVE-2026-64564 | 9.8 | Windows | CVE-2026-64564 involves a vulnerability in the SCTP (Stream Control Transmission Protocol) implementation within Microsoft Windows. The issue occurs during DEL-IP processing, where the ASCONF (Address Configuration Change Chunk) packet handling incorrectly attempts to free its own transport, potentially leading to a use-after-free or memory management error. |
| CVE-2026-64590 | 0.0 | dma-buf/udmabuf | CVE-2026-64590 identifies an issue within the dma-buf/udmabuf component where a redundant CPU synchronization triggers a cacheline EEXIST warning. This update addresses the underlying logic to ensure proper synchronization handling. |
| CVE-2026-54876 | 7.5 | Windows | CVE-2026-54876 describes a client-side memory leak vulnerability within the OCSP (Online Certificate Status Protocol) response checking mechanism in Microsoft Windows products. |
| CVE-2026-44605 | 0.0 | Rpm | CVE-2026-44605 describes a heap-based buffer overflow vulnerability located in the ndb slot table parsing logic within Rpm. This vulnerability could potentially allow for arbitrary code execution or memory corruption when processing malformed slot tables. |
| CVE-2026-64573 | 0.0 | Bluetooth | A vulnerability identified in the Bluetooth NVM tag length TLV parser leads to an underflow condition. This security update from Microsoft addresses the flaw to prevent potential memory corruption or exploitation within the Bluetooth component. |
| CVE-2026-64565 | 0.0 | ims-pcu | CVE-2026-64565 refers to a heap-based buffer overflow vulnerability located within the ims_pcu_process_data() function of the ims-pcu component, potentially allowing for memory corruption or arbitrary code execution. |
| CVE-2026-64578 | 0.0 | ksmbd | CVE-2026-64578 identifies a vulnerability in the ksmbd kernel-mode SMB server, where insufficient validation of compound request sizes before reading StructureSize2 can lead to memory safety issues. Detection engineering should focus on monitoring SMB traffic patterns for malformed or oversized requests that could trigger improper bounds handling. |


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
