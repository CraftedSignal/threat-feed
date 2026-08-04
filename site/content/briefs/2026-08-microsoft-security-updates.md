---
title: Microsoft Security Updates — August 2026
slug: 2026-08-microsoft-security-updates
description: Roundup of Microsoft security advisories published in August 2026.
date: "2026-08-01T01:41:40Z"
lastmod: "2026-08-04T01:42:32Z"
type: advisory
types:
  - advisory
severities:
  - high
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
affected_os:
  - Windows
  - Android
  - Alpine Linux
cves:
  - id: CVE-2026-62870
    cvss: 8.8
  - id: CVE-2026-65802
    cvss: 7.4
  - id: CVE-2026-66310
    cvss: 7.7
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
  - at: "2026-08-03T17:58:57Z"
    level: L2
    summary: added CVE-2026-62870
    sources:
      - anssi
    source_urls:
      - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0961/
  - at: "2026-08-03T18:03:32Z"
    level: L1
    summary: new IOCs
    sources:
      - bitdefender
    source_urls:
      - https://www.bitdefender.com/en-us/blog/labs/fake-xeno-roblox-discord-executor
  - at: "2026-08-03T22:22:14Z"
    level: L2
    summary: poc_available; added CVE-2026-56158; OS alpine linux
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=C70098EC-8455-5303-80B5-BD82E10260AE&utm_source=rss&utm_medium=rss
  - at: "2026-08-04T01:42:30Z"
    level: L2
    summary: added CVE-2026-65802
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-65802
  - at: "2026-08-04T01:42:32Z"
    level: L2
    summary: added CVE-2026-66310
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-66310
---

Aggregated Microsoft security advisories for August 2026. CVEs from this cycle are folded
into the list below as they are published.

## Recommendation

Review affected products and apply Microsoft's August 2026 security updates.
