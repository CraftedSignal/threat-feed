---
title: EDRSilencer Execution Detected
slug: 2024-01-edrsilencer
description: The EDRSilencer tool is designed to block outbound traffic of EDR processes by leveraging Windows Filtering Platform (WFP) APIs to evade endpoint defenses.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - edr
  - defense-evasion
  - windows
vendors:
  - Microsoft
  - Carbon Black
  - SentinelOne
products:
  - Microsoft Defender
  - Carbon Black
  - SentinelOne
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
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_edrsilencer_execution.yml
rules:
  - title: EDRSilencer Execution via Process Name
    description: Detects EDRSilencer execution based on process name.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - process_creation
      - windows
  - title: EDRSilencer Execution via Command Line
    description: Detects EDRSilencer execution based on command line arguments.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - process_creation
      - windows
  - title: EDRSilencer Parent Process Detection
    description: Detects suspicious parent processes of EDRSilencer execution.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

EDRSilencer is a custom, publicly available tool inspired by the FireBlock tool from MdSec NightHawk. It blocks outbound traffic of running Endpoint Detection and Response (EDR) processes using Windows Filtering Platform (WFP) APIs. This allows attackers to potentially disable or degrade EDR functionality, hindering detection and response capabilities. The tool searches for running EDR processes and applies WFP filters to block outbound traffic, adding filters for specific processes, and removing filters either individually or globally. A custom implementation avoids file handle access issues with EDR processes by bypassing the CreateFileW API. While the tool supports a wide range of EDRs like Microsoft Defender, Carbon Black, and SentinelOne, defenders should test this detection against the EDR solutions in their environment. EDRSilencer has been tested on Windows 10 and Windows Server 2016.

## Attack Chain

1. An attacker gains initial access to a system, potentially through phishing or exploiting a vulnerability.
2. The attacker uploads or transfers the EDRSilencer tool (EDRSilencer.exe) to the compromised system.
3. The attacker executes EDRSilencer.exe with administrative privileges.
4. EDRSilencer enumerates running processes to identify target EDR solutions (e.g., Microsoft Defender, Carbon Black, SentinelOne).
5. The tool utilizes WFP APIs to create filters that block outbound network traffic for the identified EDR processes.
6. These filters prevent the EDR from communicating with its command-and-control infrastructure, hindering its ability to send alerts or receive updates.
7. The attacker performs malicious activities without EDR interference, such as lateral movement or data exfiltration.
8. The attacker may remove the filters or the tool to avoid detection after completing their objectives.

## Impact

A successful EDRSilencer attack can significantly impair an organization's security posture. By blocking the outbound traffic of EDR solutions, attackers can operate with reduced visibility and detection. This can lead to delayed incident response, increased dwell time, and greater potential for data breaches, ransomware deployment, and other malicious activities. The tool has the potential to impact a wide range of organizations using affected EDR products on Windows endpoints.

## Recommendation

*   Deploy the Sigma rules provided in this brief to your SIEM to detect EDRSilencer execution and tune them for your environment.
*   Monitor process execution logs (Sysmon Event ID 1 or Windows Event Log Security 4688) for the execution of `EDRSilencer.exe` or processes containing "*blockedr *" in their command line (as defined in the Sigma rules).
*   Implement network segmentation to limit the impact of a compromised endpoint.
*   Regularly review and update EDR configurations to ensure they are resilient against tampering.
*   Investigate any alerts related to unexpected modifications to Windows Filtering Platform (WFP) rules.
*   Enable Sysmon process creation logging to activate the rules above.
