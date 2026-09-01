---
title: Detection of Potential Remote PowerShell Sessions via WinRM
slug: 2026-09-remote-powershell-detection
description: This detection targets anomalous network connections over WinRM ports 5985 and 5986 that originate from non-network service accounts, a common indicator of unauthorized remote PowerShell execution or lateral movement.
date: "2026-09-01T12:18:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lateral-movement
  - windows
  - powershell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This could potentially indicate a remote PowerShell connection.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: Detects a process that initiated a network connection over ports 5985 or 5986.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/network_connection/net_connection_win_susp_remote_powershell_session.yml
  - https://threathunterplaybook.com/hunts/windows/190511-RemotePwshExecution/notebook.html
rules:
  - title: Detect Potential Remote PowerShell Session via WinRM
    description: Detects a process initiating a network connection over ports 5985 or 5986 from a non-network service account.
    platform: sigma
    severity: high
    tactics:
      - execution
      - lateral-movement
    techniques:
      - T1021.006
      - T1059.001
    data_sources:
      - network_connection
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the detection rule and monitor for WinRM traffic patterns in the environment
      owner: Detection Engineering
      due: 48h
      evidence: Source rule requirement
  hunt_leads:
    - lead: Identify all non-admin accounts initiating connections to WinRM ports across the fleet
      technique_id: T1021.006
      data_needed:
        - Network connection logs (Sysmon EID 3 or equivalent)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Source documentation on remote PowerShell usage
---

This detection focuses on identifying potentially malicious remote management activity within a Windows environment. Windows Remote Management (WinRM) uses TCP ports 5985 (HTTP) and 5986 (HTTPS) to facilitate remote administration, including the execution of PowerShell commands across a network. Attackers frequently abuse this functionality to perform lateral movement or execute code on remote systems. 

The detection logic monitors for network connections established to these specific ports. To reduce noise, it excludes legitimate traffic associated with the 'NETWORK SERVICE' account, which is the default service account for WinRM, as well as local-to-local traffic and specific security software processes like Avast. Security operations teams should use this telemetry to identify non-standard user accounts or unexpected processes initiating remote management sessions, which may indicate credential misuse or adversary movement.

## Impact

Successful unauthorized use of remote PowerShell can lead to remote code execution, persistence, and lateral movement across a domain, potentially resulting in full compromise of host systems or sensitive data exfiltration.

## Recommendation

* Deploy the provided Sigma rule to identify anomalous outbound network connections from workstations or servers that are not expected to perform remote administration.
* Enable Windows Filtering Platform (WFP) or network connection logging via Sysmon (Event ID 3) to capture source and destination port telemetry.
* Tune the exclusion filters to account for specific administrative tooling, automation scripts, or regional language variations of the 'NETWORK SERVICE' account name within your specific environment.
