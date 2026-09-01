---
title: Script Interpreter Initiating Local Network Connections
slug: 2026-09-wscript-local-network
description: Detection of suspicious network activity where Windows script interpreters (Wscript.exe and Cscript.exe) initiate connections to local IP ranges.
date: "2026-09-01T12:18:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - living-off-the-land
  - network-monitoring
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Detects a script interpreter (Wscript/Cscript) initiating a local network connection to download or execute a script hosted on a shared folder.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_wscript_cscript_local_connection.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/28d190330fe44de6ff4767fc400cc10fa7cd6540/atomics/T1105/T1105.md
rules:
  - title: Local Network Connection Initiated By Script Interpreter
    description: Detects Wscript.exe or Cscript.exe initiating network connections to internal/private IP ranges, which may indicate lateral movement or local payload staging.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1105
    data_sources:
      - network_connection
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule for Wscript/Cscript local network connections to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source provides logic for detecting lateral movement/staging via script interpreters
  hunt_leads:
    - lead: Search for historical process creation events where Wscript.exe or Cscript.exe spawned network connections to private IP space
      technique_id: T1105
      data_needed:
        - Process creation and Network connection logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Technique is a known method for lateral movement
---

Microsoft Windows Script Host (WSH) binaries, specifically Wscript.exe and Cscript.exe, are frequently utilized by threat actors to execute malicious scripts that facilitate lateral movement or internal payload staging. When these interpreters initiate network connections to private IP address space, it often indicates the retrieval of scripts or modules hosted on internal SMB shares or other local network resources. This behavior is characteristic of post-exploitation activity where attackers leverage trusted system binaries (Living-off-the-Land) to circumvent standard perimeter defenses. Defenders should prioritize visibility into network connections spawned by these processes, as legitimate script execution rarely requires establishing raw socket connections to local network segments.

## Impact

Successful exploitation allows an attacker to fetch and execute secondary payloads within an internal network segment, facilitating lateral movement and persistence. This technique helps bridge the gap between initial access and deeper environment compromise, increasing the difficulty for detection tools that only monitor external egress traffic.

## Recommendation

1. Deploy the provided Sigma rule to detect Wscript or Cscript processes initiating local network connections.
2. Baseline internal script execution to identify legitimate administrative tasks, such as logon scripts or local automation, to reduce false positives.
3. Enable process-level network connection logging (e.g., Sysmon Event ID 3 or EDR telemetry) to correlate process origin with network socket destination.
4. Restrict or monitor outbound SMB/RPC connections originating from non-administrative endpoints to sensitive internal file shares.
