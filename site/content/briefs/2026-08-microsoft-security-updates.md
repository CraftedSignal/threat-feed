---
title: Microsoft Security Updates — August 2026
slug: 2026-08-microsoft-security-updates
description: Roundup of Microsoft security advisories published in August 2026.
date: "2026-08-01T01:41:40Z"
lastmod: "2026-08-03T18:03:32Z"
type: advisory
types:
  - advisory
severities:
  - high
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
affected_os:
  - Windows
  - Android
cves:
  - id: CVE-2026-62870
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
  - at: "2026-08-03T13:04:39Z"
    level: L1
    summary: new product
    sources:
      - therecord
    source_urls:
      - https://therecord.media/russian-wifi-hackers-hotels
  - at: "2026-08-03T17:53:45Z"
    level: L1
    summary: new product
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_wsl_bash_exec.toml
  - at: "2026-08-03T17:53:48Z"
    level: L1
    summary: new product
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_windows_powershell_susp_args.toml
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
---

Aggregated Microsoft security advisories for August 2026. CVEs from this cycle are folded
into the list below as they are published.

## Recommendation

Review affected products and apply Microsoft's August 2026 security updates.
