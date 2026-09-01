---
title: Suspicious Outbound Network Connections Initiated by Script Interpreters
slug: 2026-09-wscript-cscript-outbound
description: Adversaries utilize Windows script engines, wscript.exe and cscript.exe, to initiate outbound network connections for downloading malicious payloads or communicating with command and control infrastructure.
date: "2026-09-01T11:05:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - windows
  - c2
  - living-off-the-land
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Adversaries may use script to download malicious payloads.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_wscript_cscript_outbound_connection.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/28d190330fe44de6ff4767fc400cc10fa7cd6540/atomics/T1105/T1105.md
rules:
  - title: Detect Outbound Network Connection Initiated By Script Interpreter
    description: Detects wscript.exe or cscript.exe opening a network connection to non-local or non-Microsoft ranges.
    platform: sigma
    severity: high
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
    - SOC
  immediate_actions:
    - action: Deploy Sigma rule for outbound script interpreter connections
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific WSH and network criteria
  hunt_leads:
    - lead: Search for historical network connections initiated by wscript.exe or cscript.exe
      technique_id: T1105
      data_needed:
        - Network connection logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Commonly used for C2 and payload delivery
---

Windows Script Host (WSH) engines, specifically wscript.exe and cscript.exe, are frequently leveraged by adversaries to facilitate malicious operations within compromised environments. Because these binaries are signed, trusted, and built-in components of the Windows operating system, they are commonly used to execute scripts that retrieve secondary payloads from remote servers or establish command and control (C2) channels. This activity is a common indicator of the staging or delivery phase of an attack. Defenders should prioritize visibility into network connections initiated by these processes, as benign use of VBScript or JScript for external network communication is increasingly uncommon in modern enterprise environments. Monitoring these processes for non-local network traffic can help identify initial access or persistence mechanisms attempting to beacon out or pull down further tooling.

## Impact

Successful abuse of script interpreters allows attackers to bypass application execution restrictions, evade basic security controls, and establish persistent access. If left undetected, this activity leads to the deployment of follow-on malware, data exfiltration, or lateral movement within the network.

## Recommendation

Deploy detection rules to identify and investigate outbound network connections originating from wscript.exe or cscript.exe processes. Ensure that network telemetry (e.g., Sysmon Event ID 3 or equivalent firewall logs) is integrated into your SIEM and that local/private IP ranges are excluded from alerts to reduce noise. Investigate any instances where these interpreters attempt to contact external IP addresses, particularly those not associated with known update services or enterprise-approved infrastructure.
