---
title: Microsoft Security Updates — August 2026
slug: 2026-08-microsoft-security-updates
description: Roundup of Microsoft security advisories published in August 2026.
date: "2026-08-01T01:41:40Z"
lastmod: "2026-08-03T17:53:45Z"
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
affected_os:
  - Windows
  - Android
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
ioc_counts:
  domain: 10
  ip: 2
updates:
  - at: "2026-08-02T23:52:04Z"
    level: L2
    summary: azure kubernetes service version AKS
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/credential_access_azure_aks_coredns_configmap_modified.toml
  - at: "2026-08-03T10:03:02Z"
    level: L1
    summary: OS android
    sources:
      - securityweek
    source_urls:
      - https://www.securityweek.com/russian-state-apt-linked-to-recent-public-wi-fi-gateway-hacking/
  - at: "2026-08-03T11:58:30Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2617
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
---

Aggregated Microsoft security advisories for August 2026. CVEs from this cycle are folded
into the list below as they are published.

## Recommendation

Review affected products and apply Microsoft's August 2026 security updates.
