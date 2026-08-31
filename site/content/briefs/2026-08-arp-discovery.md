---
title: Detection of Network Connection Discovery via Arp.exe
slug: 2026-08-arp-discovery
description: Adversaries utilize the native Windows 'arp.exe' utility to perform network reconnaissance, mapping active hosts to facilitate lateral movement within compromised environments.
date: "2026-08-31T11:52:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - reconnaissance
  - living-off-the-land
  - discovery
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1049
    technique_name: System Network Connections Discovery
    evidence: Monitoring this activity is significant because both Red Teams and adversaries use arp.exe for situational awareness and Active Directory discovery.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic logic for T1049 detection.
  hunt_leads:
    - lead: Search for historical execution patterns of arp.exe in process logs.
      technique_id: T1049
      data_needed:
        - Process creation events
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Standard hunting practice for discovery techniques.
---

Adversaries and Red Teams frequently utilize living-off-the-land techniques to conduct internal network reconnaissance. The Windows utility `arp.exe`, when executed with arguments such as `-a` or `/a`, allows an attacker to display current ARP entries and identify active IP addresses and associated physical addresses within the local network segment. This behavior is a common precursor to lateral movement, allowing attackers to perform situational awareness and identify targets for further exploitation. This activity has been observed in various post-exploitation scenarios, including campaigns by actors such as Volt Typhoon and during the deployment of ransomware such as IcedID and Interlock. Monitoring for this behavior is critical for early detection of reconnaissance activities within the network perimeter.

## Attack Chain

1. Initial access is established on the target host through phishing, exploitation of public-facing applications, or credential theft.
2. The attacker establishes a command-and-control (C2) channel to interact with the compromised system.
3. The attacker executes `arp.exe -a` to enumerate local network connections and identify neighboring devices.
4. The attacker parses the output of the ARP table to map the local network topology and identify high-value targets.
5. The attacker uses the discovered information to perform port scanning or service enumeration on internal assets.
6. The attacker leverages identified services to move laterally through the network, typically using stolen credentials.
7. The final objective is achieved, such as data exfiltration or the deployment of ransomware.

## Impact

Successful network discovery allows attackers to map internal network segments, identify active critical infrastructure, and plan targeted lateral movement. This reconnaissance significantly increases the probability of a successful secondary infection or data exfiltration event, potentially impacting the confidentiality and availability of internal corporate assets.

## Recommendation

Deploy the provided Sigma rule to monitor for suspicious `arp.exe` command-line patterns across all Windows endpoints. Ensure that EDR or Sysmon telemetry is configured to capture full command-line arguments and parent process information. Tune the detection logic to account for baseline administrative activity, such as legitimate network troubleshooting scripts or tools used by IT operations teams.

## Rules

- title: "Detect Network Connection Discovery via Arp.exe"
 description: "Detects execution of arp.exe with command-line arguments used to display the ARP cache, indicating potential reconnaissance activity."
 logsource:
 category: "process_creation"
 product: "windows"
 detection:
 selection:
 Image|endswith: "\\arp.exe"
 CommandLine|contains:
 - "-a"
 - "-g"
 - "/a"
 - "/g"
 condition: "selection"
 level: "medium"
 tags:
 - "attack.discovery"
 - "attack.t1049"
 tests:
 positive:
 - name: "Execution of arp.exe with -a flag"
 data:
 - Image: "C:\\Windows\\System32\\arp.exe"
 CommandLine: "arp.exe -a"
 negative:
 - name: "Legitimate benign process execution"
 data:
 - Image: "C:\\Windows\\System32\\ping.exe"
 CommandLine: "ping 127.0.0.1"
 falsepositives:
 - "Network administrators or power users performing legitimate troubleshooting tasks."
 handoff:
 detection_confidence: "medium"
 required_telemetry:
 - log_source: "Sysmon process_creation"
 event_or_channel: "Event ID 1"
 required_fields:
 - "Image"
 - "CommandLine"
 availability: "available"
 notes: "Must capture full command line arguments."
 validation:
 status: "test_defined"
 steps:
 - "Execute 'arp.exe -a' in a test environment."
 expected_telemetry: "Event ID 1 showing the command execution."
 pass_criteria: "Detection rule triggers for the executed command."
 tuning:
 - source: "IT Administration"
 guidance: "Exclude known administrative service accounts or IT management workstation IP ranges if they perform frequent network diagnostics."
 suggested_owner: "Detection Engineering"
