---
title: Microsoft Security Updates — August 2026
slug: 2026-08-microsoft-security-updates
description: Roundup of Microsoft security advisories published in August 2026.
date: "2026-08-01T01:41:40Z"
lastmod: "2026-08-07T01:29:55Z"
type: threat
types:
  - threat
severities:
  - high
cpes:
  - cpe:2.3:a:microsoft:edge_chromium:*:*:*:*:*:*:*:*
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
affected_os:
  - Windows
  - Android
  - Alpine Linux
cves:
  - id: CVE-2026-50481
    cvss: 9.9
  - id: CVE-2026-62870
    cvss: 8.8
    epss: 0.00837
  - id: CVE-2026-65802
    cvss: 7.4
    epss: 0.00942
  - id: CVE-2026-66310
    cvss: 7.7
    epss: 0.00402
  - id: CVE-2026-66322
    cvss: 7.1
    epss: 0.00264
  - id: CVE-2026-66321
    cvss: 7.4
    epss: 0.00943
  - id: CVE-2026-66318
    cvss: 8.1
    epss: 0.00368
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
  - at: "2026-08-07T01:29:42Z"
    level: L1
    summary: new product
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-62830
  - at: "2026-08-07T01:29:45Z"
    level: L1
    summary: new product
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-62873
  - at: "2026-08-07T01:29:47Z"
    level: L1
    summary: new product
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-62896
  - at: "2026-08-07T01:29:50Z"
    level: L1
    summary: new product
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-63508
  - at: "2026-08-07T01:29:55Z"
    level: L1
    summary: new product
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-68823
---

This roundup covers 10 Microsoft security vulnerabilities. None are reported as actively exploited at the time of release. The issues affect Azure Active Directory, Azure Logic Apps, Azure SRE Agent, Azure Service Bus, Microsoft 365 Admin Center, Microsoft Entra Provisioning Service, Microsoft Planetary Computer Pro, Microsoft Teams, Power Apps.

## Summary

| CVE | CVSS | Product | Summary |
|-----|------|---------|---------|
| CVE-2026-50481 | 9.9 | Azure Active Directory | CVE-2026-50481 is a critical vulnerability in Microsoft Azure Active Directory involving the modification of assumed-immutable data (MAID). An authorized attacker can exploit this flaw to escalate privileges within the environment over a network, potentially leading to unauthorized administrative access. |
| CVE-2026-50515 | 0.0 | Azure Service Bus | CVE-2026-50515 is a critical deserialization of untrusted data vulnerability in Azure Service Bus that permits an authenticated attacker with low privileges to achieve remote code execution. Detection efforts should focus on monitoring anomalous serialized data payloads sent to service bus endpoints and unexpected process execution spawned by the Azure Service Bus service account. |
| CVE-2026-56161 | 0.0 | Azure Logic Apps | CVE-2026-56161 describes an improper access control vulnerability in Microsoft Azure Logic Apps. An authenticated attacker can exploit this vulnerability to disclose sensitive information over a network. The vulnerability carries a CVSS 3.1 base score of 9.6, indicating a critical risk. |
| CVE-2026-59115 | 0.0 | Microsoft Entra Provisioning Service | CVE-2026-59115 is a critical path traversal vulnerability in the Microsoft Entra Provisioning Service (SyncFabric). An authorized attacker can leverage this vulnerability by using a specific input string ('.../...//') to elevate their privileges over a network. The vulnerability has a CVSS base score of 9.9, indicating a significant risk to the integrity, confidentiality, and availability of the affected cloud service. |
| CVE-2026-59118 | 0.0 | Power Apps | CVE-2026-59118 is an improper authorization vulnerability in Microsoft Power Apps that allows an unauthorized attacker to perform a privilege escalation over a network. The vulnerability carries a CVSS 3.1 base score of 9.3, indicating a critical severity impact on confidentiality and integrity, necessitating restricted access controls within the affected cloud service. |
| CVE-2026-62830 | 0.0 | Azure SRE Agent | A vulnerability in the Azure SRE Agent stemming from missing authorization (CWE-862) allows an already authorized network attacker to perform privilege escalation. The vulnerability is rated critical with a CVSS 3.1 score of 9.9, as it enables full scope impact across confidentiality, integrity, and availability within the cloud environment. |
| CVE-2026-62873 | 0.0 | Microsoft 365 Admin Center | The Microsoft 365 Admin Center is vulnerable to an improper verification of cryptographic signature vulnerability (CWE-347). This flaw allows a remote, unauthorized attacker to elevate their privileges over a network, potentially leading to full compromise of confidentiality, integrity, and availability. |
| CVE-2026-62896 | 0.0 | Microsoft Teams | Microsoft Teams contains an improper authentication vulnerability that allows an authenticated attacker to perform privilege escalation over a network. This flaw represents a critical security risk due to the potential for unauthorized access elevation within the application environment. |
| CVE-2026-63508 | 0.0 | Microsoft Planetary Computer Pro (GeoCatalog) | Microsoft Planetary Computer Pro (GeoCatalog) contains a vulnerability due to missing authentication for a critical function. This allows an unauthorized attacker to perform privilege escalation over a network. The vulnerability is classified as critical and has a CVSS base score of 10.0. |
| CVE-2026-65667 | 0.0 | Microsoft Teams | CVE-2026-65667 is a critical security vulnerability in Microsoft Teams involving missing authorization (CWE-862). This flaw allows a remote, unauthenticated attacker to elevate privileges over a network, potentially leading to unauthorized access to sensitive information and system integrity compromises. |


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
