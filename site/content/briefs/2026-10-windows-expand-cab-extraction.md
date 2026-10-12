---
title: Abuse of expand.exe for Malicious Payload Staging
slug: 2026-10-windows-expand-cab-extraction
description: APT37 leverages the native Windows expand.exe utility to extract malicious CAB archives into common staging directories like C:\ProgramData as a precursor to persistence and execution.
date: "2026-10-12T18:03:08Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - APT37
tags:
  - APT37
  - defense-evasion
  - execution
  - windows
  - living-off-the-land
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1140
    technique_name: Deobfuscate/Decode Files or Information
    evidence: Detects usage of expand.exe to extract Microsoft Cabinet (CAB) archives.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: This behavior is a strong signal for ingress tool transfer and staging of payloads.
    confidence_band: high
references:
  - https://www.zscaler.com/blogs/security-research/apt37-targets-windows-rust-backdoor-and-python-loader
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1140/T1140.yaml#L304
rules:
  - title: Detect Suspicious expand.exe Extraction to ProgramData
    description: Detects the use of expand.exe to extract CAB files into C:\ProgramData, a technique used by APT37 to stage malicious payloads.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1140
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
    - action: Deploy Sigma rule to identify expand.exe abuse.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific command-line flags and target directories.
  hunt_leads:
    - lead: Search for historical process creation events of expand.exe with file extraction flags.
      technique_id: T1140
      data_needed:
        - Sysmon Event ID 1
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: APT37 activity confirmed by source.
---

APT37 has been observed utilizing the built-in Windows utility expand.exe to facilitate the deployment of malicious payloads. This technique involves the extraction of Microsoft Cabinet (CAB) files, such as 'wonder.cab', directly into staging directories like C:\\ProgramData. By repurposing this native binary, the threat actor aims to evade traditional signature-based detection that often targets custom or non-standard extraction tools. This activity is a critical indicator of ingress tool transfer and the preparation phase of an attack chain, allowing for the subsequent execution of Rust-based backdoors or loaders. Defenders should monitor for command-line arguments involving the '/F:*' or '-F:*' flags when invoked by unexpected or suspicious parent processes.

## Attack Chain

1. Attacker establishes initial access via spearphishing or exploit vector.
2. Malicious CAB archive (e.g., wonder.cab) is downloaded to a temporary directory on the victim host.
3. Attacker executes expand.exe using command-line arguments to extract all files (e.g., expand.exe -F:* [path_to_cab] C:\\ProgramData).
4. Malicious payloads and secondary scripts are unpacked into the C:\\ProgramData staging area.
5. Attacker executes the staged binary or script via command-line or service creation to establish persistence.
6. The primary malware (e.g., Rust-based backdoor) initiates callback to command-and-control infrastructure.
7. Attacker performs discovery or exfiltration activities based on the specific campaign objectives.

## Impact

Successful exploitation allows for the covert staging and execution of secondary payloads, including backdoors and loaders, leading to potential full system compromise, data theft, and persistent monitoring of the victim environment. APT37 targeting focuses on strategic intelligence gathering and operations against various sectors, often impacting multiple organizations simultaneously during coordinated campaigns.

## Recommendation

* Deploy the Sigma rule below to detect suspicious expand.exe activity targeting common staging directories.
* Enable Sysmon Event ID 1 (Process Creation) with command-line logging across all endpoints to ensure visibility into utility arguments.
* Baseline the usage of expand.exe in the environment to differentiate legitimate software update routines from unauthorized archive extraction.
* Audit C:\\ProgramData and similar temp directories for anomalous file creation patterns following process creation alerts.
