---
title: 'You do surprise me.exe: Unexpected Crypto-Miner in Hola Browser'
slug: 2026-06-hola-browser-cryptominer
description: Sophos X-Ops discovered that Hola Browser version 1.251.91.0 was distributed with an undeclared crypto-mining executable, me.exe, due to a supply chain compromise, leading to resource hijacking on affected Windows systems.
date: "2026-06-14T09:42:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain-compromise
  - cryptomining
  - pua
  - windows
  - executable
vendors:
  - Hola
products:
  - Hola Browser (version 1.251.91.0)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: ""
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: ""
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: ""
  - tactic_id: TA0040
    tactic_name: Resource Hijacking
    technique_id: T1496
    technique_name: Resource Hijacking
references:
  - https://www.sophos.com/en-us/blog/you-do-surprise-me-exe-an-unexpected-executable-in-hola-browser
iocs:
  - type: hash_sha256
    value: e3541caf708c075f0bb22fc68b03acd8457fea7cf0732ea935b1eb016d1c7721
  - type: file_path
    value: C:\Program Files\Hola\me.exe
  - type: file_path
    value: C:\Program Files\Hola\HolaMonitorService.exe
  - type: service_name
    value: hola_monitor_svc
ioc_counts:
  file_path: 2
  hash_sha256: 1
  service_name: 1
rules:
  - title: Detect Hola Browser Bundled Crypto-Miner Execution
    description: Detects the execution of the `me.exe` crypto-miner or its persistent variant `HolaMonitorService.exe`, known to be bundled with compromised Hola Browser installations.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
      - resource_hijacking
    techniques:
      - T1059
      - T1195.002
      - T1496
    data_sources:
      - process_creation
      - windows
  - title: Detect Hola Crypto-Miner Service Creation via Registry
    description: Detects the creation or modification of Windows Registry keys for the 'hola_monitor_svc' service, pointing to the bundled crypto-miner for persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - resource_hijacking
    techniques:
      - T1496
      - T1543.003
    data_sources:
      - registry_set
      - windows
  - title: Detect Windows Defender Exclusion for Hola Path
    description: Detects attempts to configure Windows Defender exclusions for the 'C:\Program Files\Hola\' directory, a tactic used by the bundled crypto-miner.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Sophos X-Ops recently uncovered a supply chain compromise affecting Hola Browser (version 1.251.91.0) during an AppEsteem certification test. An undeclared and unsigned executable, `me.exe`, was found bundled with the browser installer and subsequently dropped to `C:\Program Files\Hola\`. Analysis revealed `me.exe` to be a crypto-miner, identified by Sophos as Troj/GoMiner-B, which included characteristics such as obfuscated code and memory-write capabilities. This compromise, affecting approximately 0.1% of Hola Browser users, was attributed to anomalous activity within Hola's update distribution pipeline. Hola has since rectified the issue, rebuilt its pipeline, and implemented enhanced security measures to prevent future occurrences, with an independent forensic investigation corroborating the supply chain compromise.

## Attack Chain

1.  **Initial Access / Delivery**: Users download Hola Browser version 1.251.91.0, which, due to a supply chain compromise in Hola's distribution pipeline, includes the undeclared crypto-miner `me.exe`.
2.  **Execution**: During the browser installation or initial launch, `me.exe` is dropped onto the system, typically in `C:\Program Files\Hola\`.
3.  **Persistence Setup**: `me.exe` copies itself to `C:\Program Files\Hola\HolaMonitorService.exe` to masquerade as a legitimate component.
4.  **Persistence / Service Creation**: The `HolaMonitorService.exe` binary creates a new Windows service named `hola_monitor_svc`, configured to automatically start and execute when the host is idle.
5.  **Defense Evasion**: The crypto-miner performs actions to create exclusions for itself within Windows Defender, aiming to prevent detection and termination.
6.  **Resource Hijacking**: Once persistent and active, the `hola_monitor_svc` service (running `HolaMonitorService.exe`), an XMRig-based crypto-miner, begins mining cryptocurrency during periods of system idleness.
7.  **Impact**: The crypto-mining activity consumes significant CPU and GPU resources, leading to degraded system performance, increased power consumption, and potentially reduced hardware lifespan for the victim.

## Impact

The primary impact of this compromise was resource hijacking on affected user systems. The `me.exe` crypto-miner, identified as Troj/GoMiner-B, consumed CPU and GPU resources to mine cryptocurrency, leading to severe degradation in system performance, increased electricity consumption, and potential hardware wear-and-tear for the estimated 0.1% of affected users. Beyond direct system performance, the supply chain compromise eroded user trust in a widely used application and highlighted the risks inherent in software distribution channels. Although Hola reported no user data was accessed or exfiltrated, the presence of an unauthorized executable posed a significant security risk, allowing an attacker to run arbitrary code on user machines.

## Recommendation

*   Deploy the Sigma rules provided in this brief to your SIEM for detection of `me.exe` execution, `HolaMonitorService.exe` creation, and `hola_monitor_svc` service registration.
*   Enable Sysmon event logging for `process_creation` (Event ID 1), `file_creation` (Event ID 11), and `registry_set` (Event ID 13) to ensure telemetry for the rules in this brief.
*   Review systems for the presence of `me.exe` (SHA256: `e3541caf708c075f0bb22fc68b03acd8457fea7cf0732ea935b1eb016d1c7721`) or `HolaMonitorService.exe` in `C:\Program Files\Hola\`.
*   Ensure Hola Browser installations are updated to versions released after the fix to prevent exposure to the compromised distribution pipeline.
