---
title: 'GigaWiper: Multi-Payload Destructive Backdoor'
slug: 2026-07-gigawiper
description: GigaWiper is a sophisticated, Golang-based destructive backdoor observed since October 2025 by Microsoft Threat Intelligence, that combines robust command-and-control (C2) capabilities with multiple destructive payloads, including physical disk wiping, ransomware-like encryption derived from Crucio, and multi-pass secure wiping reimplemented from FlockWiper.
date: "2026-07-09T15:51:46Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wiper
  - destructive
  - backdoor
  - ransomware
  - golang
  - windows
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: It then creates a new scheduled task named OneDrive Update by running the following command before printing “Task created. Original process exiting.” and exiting the process. The scheduled task is configured to essentially run every minute in addition to running once on system startup.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The backdoor creates and uses the registry key HKCU\SOFTWARE\OneDrive\Environment to track its execution count. If the key is absent on the system, the malware determines that it’s running on the system for the first time and proceeds to create the key, setting it to “0”.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Beyond destructive functionality, the backdoor sets persistence and implements C2 communication over RabbitMQ and Redis.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: The standalone wiper operates at the physical disk level, overwriting raw disk content and removing partition metadata.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
    evidence: A destructive command that derives from Crucio ransomware and encrypts files with randomly generated keys that are never saved, making decryption impossible.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
    evidence: After it finishes wiping the drives, the malware forces an immediate reboot by invoking Windows shutdown functionality with restart and zero-delay options.
    confidence_band: high
references:
  - https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
iocs:
  - type: registry_key
    value: HKCU\SOFTWARE\OneDrive\Environment
  - type: scheduled_task
    value: OneDrive Update
ioc_counts:
  registry_key: 1
  scheduled_task: 1
rules:
  - title: GigaWiper Scheduled Task Persistence Creation
    description: Detects the creation of the 'OneDrive Update' scheduled task by GigaWiper for persistence, commonly observed through 'schtasks.exe'.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
  - title: GigaWiper Forced System Reboot
    description: Detects GigaWiper's attempt to force a system reboot using the shutdown command, often with immediate and forceful parameters.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1489
    data_sources:
      - process_creation
      - windows
  - title: GigaWiper Registry Key Tracking for Persistence
    description: Detects modifications to the 'HKCU\SOFTWARE\OneDrive\Environment' registry key used by GigaWiper to track execution count and manage persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1112
    data_sources:
      - registry_set
      - windows
rules_count: 3
---

Since October 2025, Microsoft Threat Intelligence has been tracking GigaWiper, a highly destructive Golang-based backdoor that consolidates multiple wiper and ransomware-like capabilities. This implant stands out for its modular design, merging code from previously distinct malware families such as a standalone physical disk wiper, a destructive component derived from Crucio ransomware that encrypts files with unrecoverable keys, and a multi-pass secure wiping logic reimagined from FlockWiper. GigaWiper establishes persistence via a scheduled task and a registry key, communicating with its command-and-control (C2) infrastructure over RabbitMQ and Redis. This consolidation into a single platform reflects an operational efficiency trend among threat actors, aiming to reduce deployment footprints while expanding destructive potential across targeted environments.

## Attack Chain

1. Initial execution of the GigaWiper backdoor implant on a compromised system.
2. The implant checks for prior execution via the `HKCU\SOFTWARE\OneDrive\Environment` registry key and creates a scheduled task named "OneDrive Update" for persistence, running every minute and at system startup.
3. GigaWiper establishes command-and-control (C2) communication channels, utilizing RabbitMQ and Redis.
4. Upon receiving a destructive command from the C2, GigaWiper enumerates physical disk drives using Windows Management Instrumentation (WMI) queries to identify targets.
5. It proceeds to target non-Windows drives, removing their partition references via `DeviceIoControl` with `IOCTL_DISK_CREATE_DISK` to reinitialize partitioning metadata.
6. The malware then overwrites the raw content of the identified drives in 0xA00000-sized chunks, filling the first byte with randomized data and the rest with zeros, effectively destroying data.
7. In some variants, GigaWiper encrypts files using a mechanism derived from Crucio ransomware, where encryption keys are not saved, rendering data unrecoverable.
8. Finally, it forces an immediate system reboot by invoking Windows shutdown functionality with restart and zero-delay options to finalize the destructive impact.

## Impact

GigaWiper's primary impact is severe data destruction and system unavailability. Observed since October 2025, it has been used to wipe compromised environments, rendering systems inoperable and data irrecoverable. The consolidation of multiple wiping and ransomware capabilities means that organizations face a multi-pronged attack that not only deletes files and partitions but also encrypts data without any recovery possibility. This leads to significant operational disruption, data loss, and substantial recovery costs across targeted organizations. While specific victim counts or sectors are not detailed, the nature of the threat indicates potential for widespread damage across any Windows-based enterprise environment.

## Recommendation

* Deploy the provided Sigma rules to your SIEM/EDR and tune them for your environment.
* Enable Sysmon process-creation logging to capture `schtasks.exe` and `shutdown.exe` activity to activate the rules above.
* Monitor for modifications to the `HKCU\SOFTWARE\OneDrive\Environment` registry key by unfamiliar processes, leveraging `registry_set` logs.
* Implement strong egress filtering to detect and block suspicious outbound connections, particularly those to unknown RabbitMQ or Redis endpoints.
