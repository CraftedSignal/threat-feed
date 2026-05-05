---
title: EDRSilencer Execution Detected
slug: 2024-01-edrsilencer
description: EDRSilencer, a tool leveraging Windows Filtering Platform APIs to block outbound traffic of EDR processes like Microsoft Defender and Carbon Black, can be used to tamper with security solutions.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - edrsilencer
  - security-solution-tampering
  - defense-evasion
vendors:
  - Microsoft
  - VMware
products:
  - Microsoft Defender
  - Carbon Black Endpoint Standard
affected_os:
  - Windows 10
  - Windows Server 2016
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/netero1010/EDRSilencer
rules:
  - title: Detect EDRSilencer Execution via Process Name
    description: Detects EDRSilencer execution based on the process name.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - process_creation
      - windows
  - title: Detect EDRSilencer Execution via 'blockedr' Process Argument
    description: Detects EDRSilencer execution based on the presence of 'blockedr' argument, excluding known 'blockedreport' false positives.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - process_creation
      - windows
  - title: Detect EDRSilencer Using Sysmon Image Loaded Events
    description: Detects the loading of EDRSilencer.exe's image into memory, indicating its execution.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - image_load
      - windows
rules_count: 3
---

EDRSilencer is a tool designed to impair Endpoint Detection and Response (EDR) solutions by blocking their outbound network traffic. Inspired by MdSec NightHawk's FireBlock, EDRSilencer uses Windows Filtering Platform (WFP) APIs to disrupt communication from EDR processes. This tool can search for running EDR processes (including Microsoft Defender, Carbon Black, and SentinelOne), apply WFP filters to block outbound traffic, add filters for specific processes, and remove filters either individually or globally. A custom implementation helps EDRSilencer avoid file handle access issues with EDR processes by bypassing the CreateFileW API. The tool has been tested on Windows 10 and Windows Server 2016. Successful execution of EDRSilencer allows attackers to operate on compromised systems with reduced risk of detection by endpoint security solutions.

## Attack Chain

1.  Attacker gains initial access to the target system (details of initial access are not covered in the source).
2.  Attacker deploys EDRSilencer.exe to the compromised host.
3.  Attacker executes EDRSilencer.exe.
4.  EDRSilencer enumerates running processes to identify targeted EDR solutions, such as Microsoft Defender or Carbon Black.
5.  EDRSilencer leverages the Windows Filtering Platform (WFP) APIs to create filters.
6.  WFP filters block outbound network traffic from the targeted EDR processes.
7.  EDR solutions are impaired, preventing them from sending telemetry or receiving updates.
8.  Attacker performs malicious activities on the compromised host with a reduced risk of detection and response.

## Impact

Successful execution of EDRSilencer can significantly impair the effectiveness of endpoint security solutions, such as Microsoft Defender and Carbon Black. This can lead to a prolonged dwell time for attackers and an increased risk of successful data exfiltration, ransomware deployment, or other malicious activities. The source does not specify the number of victims or sectors targeted.

## Recommendation

*   Deploy the Sigma rules provided below to detect EDRSilencer execution based on process name and command-line arguments.
*   Enable process creation logging (Event ID 4688 or Sysmon Event ID 1) to capture the execution of EDRSilencer.
*   Monitor for unusual use of Windows Filtering Platform (WFP) APIs, as EDRSilencer leverages these APIs to block network traffic.
*   Investigate any instances where security solutions, such as Microsoft Defender or Carbon Black, suddenly stop reporting telemetry or receiving updates.
*   Use threat hunting queries based on observed parent processes and process paths to identify anomalous EDRSilencer activity in your environment.
