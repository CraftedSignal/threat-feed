---
brief_id: brief-2026-11-16-cloudflared-abuse-afceca7b
event_id: brief-2026-11-16-cloudflared-abuse-afceca7b
revision: 1
activity_at: "2026-11-16T17:30:20Z"
title: 'Cloudflared: Abuse of Cloudflare Tunnel for covert command-and-control'
slug: 2026-11-cloudflared-abuse-afceca7b
description: Threat actors are increasingly abusing the legitimate Cloudflare Tunnel (cloudflared) utility to establish covert command-and-control and persistent remote access by leveraging token-authenticated, configuration-backed, or Quick Tunnels.
date: "2026-11-16T17:30:20Z"
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
tags:
  - c2
  - living-off-the-land
  - endpoint
  - persistence
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1572
    technique_name: Protocol Tunneling
    evidence: Threat actors have used cloudflared for covert command-and-control and persistent remote access, including renamed binaries and tunnels that expose local services through Cloudflare's edge.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_potential_cloudflared_tunnel_execution.yml
  - https://www.bleepingcomputer.com/news/security/hackers-increasingly-abuse-cloudflare-tunnels-for-stealthy-connections/amp/
  - https://www.guidepointsecurity.com/blog/tunnel-vision-cloudflared-abused-in-the-wild/
rules:
  - title: Detect Potential Cloudflared Tunnel Execution
    description: Detects the execution of cloudflared.exe (or renamed variants) using command-line arguments indicative of tunnel establishment, such as tokens, configuration files, or local loopback proxying.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1572
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
    - action: Deploy Sigma detection rule for cloudflared execution and tune against known-good administrative base-lines.
      owner: Detection Engineering
      due: 48h
      evidence: Threat actors use renamed binaries; process name matching is insufficient alone.
  hunt_leads:
    - lead: Search for cloudflared process creation events where the original_file_name is cloudflared.exe but the process_name is altered.
      technique_id: T1572
      data_needed:
        - Endpoint Process Telemetry (Sysmon Event ID 1)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The source identifies the use of renamed binaries to evade detection.
  mitigation_plan:
    - priority: short_term
      action: Restrict the execution of cloudflared binaries to approved directories or authorized user service accounts via EDR/AppLocker policies.
      owner: IT Operations
      addresses: T1572
      evidence: The binary is frequently abused for persistent remote access.
---

## Overview
Threat actors are abusing the legitimate cloudflared binary to create persistent, stealthy network tunnels that expose local services to the internet or provide command-and-control access. This technique often involves renaming the binary to evade simple process-name allowlists and using complex command-line arguments to initiate connections.

## Impact
Attackers can achieve persistent remote access and bypass traditional firewall egress filtering by creating encrypted tunnels that originate from inside the protected network, effectively tunneling traffic through Cloudflare's edge infrastructure.

## Recommendation
- Inventory the legitimate use of cloudflared within your environment to differentiate authorized DevOps or administrative tasks from unauthorized tunnel creation.
- Implement endpoint telemetry to capture full command-line arguments for all process creation events.
- Establish monitoring for the execution of cloudflared, particularly when initiated by unusual parent processes or by users who do not perform administrative network configuration tasks.
- Alert on command-line patterns containing --token, --config, or --url combined with tunnel-related parameters.
