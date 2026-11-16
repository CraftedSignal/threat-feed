---
brief_id: brief-2026-11-16-ngrok-reverse-proxy
event_id: brief-2026-11-16-ngrok-reverse-proxy
revision: 1
activity_at: "2026-11-16T17:21:51Z"
title: Ngrok Reverse Proxy Usage for Post-Exploitation
slug: 2026-11-ngrok-reverse-proxy
description: Threat actors are increasingly leveraging the legitimate remote-access tool 'ngrok' to establish reverse proxies, enabling C2 communication, persistence, and lateral movement while bypassing traditional network security controls.
date: "2026-11-16T17:21:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - c2
  - persistence
  - lateral-movement
  - endpoint-monitoring
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1572
    technique_name: Protocol Tunneling
    evidence: Threat actors have used ngrok to expose internal services, maintain persistence, move laterally, and proxy command-and-control traffic.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: Threat actors have used ngrok to expose internal services, maintain persistence, move laterally, and proxy command-and-control traffic.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
    evidence: Threat actors have used ngrok to expose internal services, maintain persistence, move laterally, and proxy command-and-control traffic.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/ngrok_reverse_proxy_usage.yml
rules:
  - title: Detect Ngrok Reverse Proxy Execution
    description: Detects ngrok binary execution on Linux and Windows by monitoring process names, original file names, and specific command-line tunneling patterns correlated with sensitive port access.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1090
      - T1102
      - T1572
    data_sources:
      - process_creation
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule for ngrok process and tunnel execution.
      owner: Detection Engineering
      due: 48h
      evidence: Detected behaviors are highly correlated with post-exploitation activity in incident reports.
  hunt_leads:
    - lead: Identify processes communicating with ngrok infrastructure or using known ngrok command line flags.
      technique_id: T1572
      data_needed:
        - Endpoint Process Command Line
        - Network Connection Logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Attackers utilize ngrok flags for authentication and tunnel configuration.
---

## Overview

Ngrok is a legitimate development tool frequently abused by threat actors to expose internal services, maintain long-term persistence, move laterally within a compromised network, and proxy command-and-control (C2) traffic. Attackers utilize ngrok to tunnel RDP (3389) or SMB (445) traffic, effectively bypassing firewall restrictions. Malicious use is often characterized by the deployment of the 'ngrok' binary (sometimes renamed), the execution of authentication commands, and the use of wrappers such as 'Invoke-Ngrok'. This activity has been observed in various campaigns, including those attributed to Scattered Spider and Iranian-linked threat actors.

## Recommendation

- Deploy the provided detection logic to identify unauthorized ngrok execution and tunnel configuration on endpoints.
- Establish an allowlist for authorized development or administrative use of ngrok in your environment.
- Monitor for the execution of ngrok or its common wrappers (e.g., Invoke-Ngrok) in conjunction with sensitive ports like 3389 (RDP) or 445 (SMB).
- Ingest endpoint process telemetry, including original file names and full command-line arguments, into your SIEM for behavioral analysis.
