---
title: Detection of Unauthorized Access to Azure Cloud Credentials
slug: 2026-08-cloud-credential-theft
description: Detection of uncommon processes accessing sensitive local Azure configuration and credential files, a common technique utilized by infostealers like Vidar Stealer to harvest cloud tokens.
date: "2026-08-19T22:28:14Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-theft
  - infostealer
  - cloud-security
vendors:
  - Microsoft
products:
  - Azure
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
    evidence: Access by any process outside the known toolchain may indicate credential theft or cloud identity reconnaissance activity, including infostealer behavior.
    confidence_band: high
references:
  - https://www.trendmicro.com/en_us/research/25/j/how-vidar-stealer-2-upgrades-infostealer-capabilities.html
rules:
  - title: Detect Unauthorized Access to Azure Credential Files
    description: Detects uncommon processes reading sensitive Azure configuration and token files, which may indicate infostealer activity.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1528
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable Object Access auditing for sensitive Azure configuration paths.
      owner: IT Operations
      due: 48h
      evidence: Required for Event ID 4663 generation.
  enrichment_needed:
    - item: False positive baseline for local environment
      owner: SOC
      reason: Identify legitimate automation tools to prevent noise.
      evidence: Known false positives note.
  mitigation_plan:
    - priority: short_term
      action: Review and restrict write/read permissions on user .azure directories.
      owner: IT Operations
      addresses: T1528
      evidence: Preventing unauthorized access to configuration files.
---

This threat brief focuses on the exploitation of local Azure credential storage by infostealers, specifically the Vidar Stealer malware family. Adversaries target sensitive files stored on Windows endpoints - such as access tokens, profile data, and MSAL caches - to facilitate credential theft and cloud identity reconnaissance. By reading these files, attackers can exfiltrate valid session tokens, allowing them to bypass traditional authentication mechanisms and gain unauthorized access to cloud environments. Defenders must monitor for unauthorized read operations on these specific configuration files, as legitimate cloud tooling typically operates through well-defined, predictable process paths.

## Impact

Successful exploitation allows attackers to gain persistence and unauthorized access to cloud-based resources associated with the compromised identity. This can lead to data exfiltration, lateral movement within cloud environments, and potential compromise of corporate infrastructure. The behavior is indicative of targeted infostealer campaigns that specifically prioritize high-value cloud configuration data.

## Recommendation

* Enable Windows Security Event ID 4663 and configure System Access Control Lists (SACLs) on the following paths: `%USERPROFILE%\.azure\accessTokens.json`, `%USERPROFILE%\.azure\azureProfile.json`, `%USERPROFILE%\.azure\msal_token_cache.json`, `%USERPROFILE%\.azure\TokenCache.dat`, and `%USERPROFILE%\Windows Azure Powershell\TokenCache.dat`.
* Deploy the Sigma rule below to detect unauthorized read access to the aforementioned sensitive files.
* Establish a baseline for legitimate cloud-management processes (e.g., Azure CLI, VS Code) in your environment and maintain an allowlist to minimize false positives from administrative tools.
* Investigate any detected alerts originating from unknown or non-standard process paths, focusing on potential malicious activity such as credential staging or exfiltration.
