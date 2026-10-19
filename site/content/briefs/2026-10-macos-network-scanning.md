---
title: MacOS Network Service Scanning Activity
slug: 2026-10-macos-network-scanning
description: Detection of network service discovery and enumeration activities on MacOS systems using common tools like nmap, netcat, and telnet.
date: "2026-10-19T06:51:48Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - discovery
  - macos
  - process-creation
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: Detects enumeration of local or remote network services.
    confidence_band: high
rules:
  - title: MacOS Network Service Scanning
    description: Detects enumeration of local or remote network services using nmap, telnet, or netcat scanning flags
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1046
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to monitor network discovery tools
      owner: Detection Engineering
      due: 7d
      evidence: Sigma rule provided in brief
  hunt_leads:
    - lead: Identify historical usage of network scanners across the environment
      technique_id: T1046
      data_needed:
        - process_creation logs
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: General reconnaissance TTP identification
---

This brief addresses the detection of network scanning and service enumeration techniques commonly employed during the discovery phase of an attack. On MacOS, adversaries often leverage built-in or easily obtainable binaries such as netcat (nc), nmap, or telnet to map internal networks, identify open ports, and fingerprint network services. While these tools have legitimate administrative use cases, their execution in suspicious contexts - especially when scanning for specific services or utilizing flags indicative of probing - warrants monitoring by security operations teams. Defenders should focus on baseline process creation events to differentiate authorized network troubleshooting from potential unauthorized reconnaissance.

## Impact

Successful network scanning allows adversaries to gain situational awareness of the target environment, identify high-value targets (such as databases or administrative interfaces), and facilitate lateral movement or exploitation of discovered services. While this behavior itself does not imply a compromise, it is a precursor to more severe malicious activities.

## Recommendation

Deploy the provided Sigma rule to your SIEM to monitor for suspicious invocation of network scanning utilities. Focus on tuning the alert by correlating these process creation events with network flow logs to identify unusual outbound scanning patterns originating from endpoint workstations.

## Detection

- Deploy the MacOS process creation detection rule provided below to identify non-listening network enumeration attempts.
