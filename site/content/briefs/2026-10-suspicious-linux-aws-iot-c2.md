---
brief_id: brief-2026-10-20-suspicious-linux-aws-iot-c2
event_id: brief-2026-10-20-suspicious-linux-aws-iot-c2
revision: 1
activity_at: "2026-10-20T23:30:58Z"
title: Suspicious Linux process connection to AWS IoT Core MQTT
slug: 2026-10-suspicious-linux-aws-iot-c2
description: Adversaries may leverage AWS IoT Core as a command-and-control rendezvous point by deploying agents on Linux hosts that utilize MQTT over TLS to relay commands through cloud-based brokers.
date: "2026-10-20T23:30:58Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - command-and-control
  - linux
  - aws
  - c2
vendors:
  - Amazon
products:
  - AWS IoT Core
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    subtechnique_id: T1071.005
    subtechnique_name: Publish/Subscribe Protocols
    evidence: Adversaries can use an attacker-controlled AWS IoT Core MQTT broker to relay commands, results, and files.
    confidence_band: high
rules:
  - title: Detect Suspicious Linux Process Connection to AWS IoT Core MQTT
    description: Detects a process running from a suspicious directory that resolves an AWS IoT Core endpoint and connects via TCP/443 or TCP/8883.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.005
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review DNS logs for unauthorized AWS IoT endpoint resolutions originating from high-risk directories.
      owner: SOC
      due: 24h
      evidence: Source provides specific patterns for AWS IoT endpoint resolutions.
  enrichment_needed:
    - item: Packet-level inspection of ALPN tokens
      owner: SOC
      reason: Confirming ALPN x-amzn-mqtt-ca verifies the intent of the connection.
      evidence: Source documentation on investigative steps.
  hunt_leads:
    - lead: Search for X.509 certificate files recently created in tmp or user-writable directories.
      technique_id: T1071.005
      data_needed:
        - File system events
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Source investigation guide highlights certificate placement.
  mitigation_plan:
    - priority: short_term
      action: Implement strict egress filtering for known malicious AWS IoT endpoints.
      owner: IT Operations
      addresses: Command and Control infrastructure
      evidence: Source advice on blocking endpoint domains.
  gaps:
    - Visibility into encrypted traffic without TLS inspection.
---

Adversaries are increasingly using AWS IoT Core as a covert command-and-control (C2) channel for compromised Linux hosts. By provisioning an attacker-controlled broker and deploying an agent - typically running from non-standard or writable directories such as /tmp, /dev/shm, or hidden user paths - the threat actor can communicate with the compromised asset via MQTT over TLS. This method allows for the relay of commands, execution results, and file transfers without requiring a direct connection to a dedicated operator backend server. Because AWS IoT endpoints are publicly resolvable and facilitate legitimate cloud traffic, this communication often blends in with standard business operations. The use of port 443 or 8883 for MQTT traffic further complicates network-based detection, necessitating focus on the correlation between endpoint behavior, specific process execution paths, and cloud-based infrastructure resolution.

## Attack Chain

1. The adversary gains initial access to the Linux host and executes a malicious binary or script from a high-entropy or writable path like /tmp or a hidden user directory.
2. The malicious process retrieves the target AWS IoT Core data endpoint, which is uniquely formatted for the attacker's specific AWS account and region.
3. The process initiates a DNS query to resolve the account-specific AWS IoT data endpoint (e.g., &lt;prefix>-ats.iot.&lt;region>.amazonaws.com).
4. Upon receiving the resolved IP addresses from the DNS request, the process initiates an outbound TCP connection to one of these addresses.
5. The connection is established over standard ports 443 or 8883, which are used for MQTT over TLS.
6. The agent performs an MQTT handshake and subscribes to specific topics for C2 instruction and command execution.
7. The attacker issues commands through the AWS IoT broker, which the agent executes, returning the output via the established MQTT channel.

## Impact

Successful deployment of this C2 mechanism enables persistent, covert remote access to compromised infrastructure. Organizations targeted include those running Linux-based environments where unauthorized agents can be introduced via exploitation or credential compromise. If unchecked, this activity facilitates data exfiltration, lateral movement, and arbitrary command execution while bypassing traditional perimeter security controls that rely on blocking known malicious IP infrastructure.

## Recommendation

Prioritized actions for detection engineering teams:

- Deploy the provided Sigma-compatible detection logic to identify processes running from suspicious paths that resolve and connect to AWS IoT infrastructure.
- Implement network monitoring to flag unexpected outbound connections to known AWS IoT data endpoint address patterns, especially when initiated by non-standard processes.
- Enrich security event telemetry with packet-level inspection to identify the ALPN value "x-amzn-mqtt-ca" on port 443 connections, which indicates AWS IoT MQTT usage.
- Review file system integrity and execution policies to prevent the execution of binaries from volatile or user-writable directories.
