---
title: Abuse of Azure Storage Utilities for Data Exfiltration
slug: 2026-09-azcopy-exfiltration
description: Threat actors, including Rhysida and Storm-0501, abuse native Microsoft Azure storage utilities as living-off-the-land binaries to exfiltrate data from compromised endpoints to attacker-controlled cloud storage.
date: "2026-09-11T00:48:21Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Rhysida
tags:
  - exfiltration
  - ransomware
  - living-off-the-land
  - cloud-security
vendors:
  - Microsoft
products:
  - AzCopy
  - Azure Storage Explorer
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Threat actors abuse AzCopy and Azure Storage Explorer to exfiltrate data from compromised environments to attacker-controlled Azure storage accounts.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: These Microsoft utilities are legitimate data-transfer tools; ransomware operators drop portable copies and use SAS-authenticated jobs to pull data from victim storage.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Actors run azcopy copy with SAS URLs against Azure storage endpoints.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-319a
  - https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
rules:
  - title: Detect Suspicious AzCopy or Azure Storage Explorer Usage
    description: Detects the first-time execution of AzCopy or Azure Storage Explorer on a Windows host, a technique used by ransomware actors to exfiltrate data to Azure storage accounts.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM and tune against common administrative baseline.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific command-line arguments to monitor for AzCopy.
  hunt_leads:
    - lead: Search for non-standard process paths for azcopy.exe or StorageExplorer.exe.
      technique_id: T1059
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source mentions actors drop portable copies under unusual paths.
  mitigation_plan:
    - priority: short_term
      action: Restrict outbound network access for storage-related utilities to approved storage account endpoints.
      owner: IT Operations
      addresses: T1567.002
      evidence: Source identifies SAS URLs as the mechanism for data movement.
---

Threat actors, specifically ransomware operators such as Rhysida and Storm-0501, are increasingly utilizing Microsoft Azure storage utilities - AzCopy and Azure Storage Explorer - to facilitate large-scale data exfiltration. These tools, which are legitimate administrative utilities, are leveraged as living-off-the-land binaries to bypass security controls. Attackers drop portable copies of these binaries onto victim machines or utilize pre-installed versions to initiate SAS-authenticated transfers. By issuing `azcopy copy` or `azcopy sync` commands against Azure Blob, Data Lake, or File storage endpoints, actors can pull data from compromised local environments or directly pull/push data between Azure storage containers to attacker-controlled infrastructure. The use of native, digitally signed binaries allows adversaries to blend in with legitimate administrative activity while bypassing standard file-based reputation filters.

## Attack Chain

1. Attacker gains initial access and establishes persistence on a Windows endpoint.
2. Attacker performs reconnaissance to identify sensitive data locations on local disks or mapped Azure storage shares.
3. Attacker drops a portable, legitimate copy of `azcopy.exe` or uses the existing Azure Storage Explorer application.
4. Attacker crafts a command-line string including the target storage account, destination container, and a malicious SAS URL for authentication.
5. Attacker executes `azcopy` or launches `StorageExplorer.exe` to initiate the data transfer.
6. Data is exfiltrated directly to an attacker-controlled Azure storage account using authenticated cloud APIs.
7. Attacker removes the staging binaries to minimize footprint and clear indicators of exfiltration activity.

## Impact

Successful exfiltration via these utilities results in the compromise of sensitive corporate and PII data stored within Azure environments. Attacks observed in the wild have led to substantial data theft from impacted organizations, which is subsequently leveraged for double-extortion ransomware operations. The speed of these tools allows for the exfiltration of large volumes of data in a short timeframe, significantly increasing the potential blast radius of a single compromised endpoint.

## Recommendation

Detection engineering teams should monitor for the first-time execution of cloud sync tools on critical infrastructure.
- Implement the provided Sigma rule to identify abnormal execution of Azure storage tools on Windows hosts.
- Baseline administrative usage of AzCopy and Azure Storage Explorer to distinguish between authorized cloud migration tasks and malicious exfiltration.
- Investigate any process spawning these utilities from non-standard paths or when initiated by PowerShell/cmd.exe in an automated scripting context.
- Correlate endpoint-based execution alerts with Azure Storage diagnostic logs, specifically looking for `GetBlob`, `PutBlob`, or `BlobBlob` activity using `AzCopy` or `Microsoft Azure Storage Explorer` user agents.
