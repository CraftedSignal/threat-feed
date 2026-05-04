---
title: Execution from Removable Media with Network Connection
slug: 2024-01-removable-media-execution
description: Detects process execution from removable media by an unusual process with untrusted code signature followed by network connection attempts, potentially indicating malware introduced via removable media for initial access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - initial-access
  - removable-media
  - windows
vendors:
  - Elastic
products:
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1091
    technique_name: Replication Through Removable Media
references:
  - https://attack.mitre.org/techniques/T1091/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/initial_access_execution_from_removable_media.toml
rules:
  - title: Execution from a Removable Media with Network Connection
    description: Detects process execution from a removable media, specifically USB, by a process with an untrusted code signature, followed by a network connection attempt.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1091
    data_sources:
      - process_creation
      - windows
  - title: Network Connection from Removable Media Execution
    description: Detects network connections originating from processes executed from removable media.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This detection identifies potential initial access attempts where adversaries use removable media, such as USB drives, to introduce malware into systems, potentially those on disconnected or air-gapped networks. The attack relies on copying malware to the removable media and taking advantage of Autorun or user execution to initiate the malicious process. The rule focuses on identifying suspicious process executions from USB devices lacking valid code signatures, followed by network connection attempts, indicating a potential attempt to establish command and control or exfiltrate data. This activity is significant as it can bypass traditional network security measures and establish a foothold within an organization's environment. The detection logic is based on Elastic Defend telemetry.

## Attack Chain

1.  An attacker copies malware onto a USB drive from an infected system.
2.  The attacker physically inserts the USB drive into a target Windows system.
3.  The user, either unknowingly or through social engineering, executes the malicious binary from the USB drive. This could be achieved through Autorun features (if enabled) or by manually clicking on an executable file.
4.  The executed process, now running on the target system, lacks a valid code signature, raising suspicion.
5.  The malicious process attempts to establish a network connection, potentially to a command and control server or to exfiltrate data.
6.  The network connection attempt is logged, capturing details about the destination IP address and port.
7.  The attacker gains initial access to the system and can potentially perform reconnaissance, privilege escalation, or lateral movement.

## Impact

A successful attack could lead to unauthorized access to sensitive data, system compromise, and potential lateral movement within the network. Although the risk score is low, such attacks on air-gapped systems are high impact. The number of victims is unknown; however, organizations across all sectors are vulnerable.

## Recommendation

*   Enable process creation and network connection logging to detect this type of activity (logs-endpoint.events.process-* and logs-endpoint.events.network-*).
*   Deploy the Sigma rule "Execution from a Removable Media with Network Connection" to your SIEM and tune for your environment.
*   Disable Autorun features on all systems to prevent automatic execution of programs from removable media.
