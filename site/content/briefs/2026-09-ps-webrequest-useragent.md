---
title: Detection of Suspicious PowerShell WebRequest User-Agent Modification
slug: 2026-09-ps-webrequest-useragent
description: Adversaries manipulate the User-Agent string in PowerShell web requests to masquerade C2 traffic as legitimate browser or application activity.
date: "2026-09-03T13:42:23Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - powershell
  - evasion
  - network-protocol
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_invoke_webrequest_useragent.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1071.001/T1071.001.md#t1071001---web-protocols
rules:
  - title: Detect Suspicious PowerShell WebRequest User-Agent Modification
    description: Detects usage of Invoke-WebRequest or Invoke-RestMethod with a custom User-Agent, which is often used to blend C2 traffic with legitimate web activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints
      owner: IT Operations
      due: 72h
      evidence: Source requirement for detection
  hunt_leads:
    - lead: Search historical logs for PowerShell scripts containing '-UserAgent' and web request cmdlets
      technique_id: T1071.001
      data_needed:
        - ScriptBlockText
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Presence of technique in adversary tradecraft
---

Adversaries frequently use PowerShell cmdlets such as Invoke-WebRequest, Invoke-RestMethod, iwr, and irm to perform C2 operations, data exfiltration, or payload delivery. To evade network-based detection, monitoring, or filtering, attackers modify the default PowerShell User-Agent string to match common browsers or legitimate software. By blending their communication patterns with standard HTTP/S traffic, they reduce the effectiveness of simple signatures targeting default PowerShell identifiers. Defenders must monitor PowerShell Script Block Logging for the combination of network-request cmdlets and the usage of the -UserAgent flag to identify potentially unauthorized outbound connections.

## Impact

Successful abuse of PowerShell for network communication facilitates C2 channel establishment, lateral movement, and data exfiltration. If left undetected, this technique allows attackers to persist within the environment while remaining concealed within standard web traffic noise.

## Recommendation

- Enable PowerShell Script Block Logging (Event ID 4104) to capture the full execution context of scripts containing web request cmdlets.
- Deploy the provided Sigma rule to your SIEM and tune against common internal administrative scripts that perform API calls with custom User-Agents.
- Baseline common internal PowerShell traffic to identify unauthorized use of Invoke-WebRequest or Invoke-RestMethod from non-administrative endpoints.
