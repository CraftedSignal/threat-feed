---
title: Abuse of WMI for Remote Process Execution
slug: 2026-10-wmi-remote-execution
description: Adversaries leverage the Windows Management Instrumentation (WMI) utility (wmic.exe) to facilitate lateral movement and remote code execution by spawning unauthorized processes on target systems.
date: "2026-10-12T17:56:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - execution
  - wmi
  - living-off-the-land
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1047
    technique_name: Windows Management Instrumentation
    evidence: WMI can be abused for lateral movement and remote code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
    evidence: This activity is significant as WMI can be abused for lateral movement and remote code execution.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1047/
  - https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/create-method-in-class-win32-process
rules:
  - title: Detect Remote Process Instantiation via WMI
    description: Detects the execution of wmic.exe with parameters indicating an attempt to spawn a process on a remote system via WMI.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1047
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
    - action: Deploy the Sigma detection rule to monitor for remote WMI process calls.
      owner: Detection Engineering
      due: 48h
      evidence: Analytic requirement for detecting lateral movement.
  hunt_leads:
    - lead: Search for wmic.exe process creation events with /node flags in logs.
      technique_id: T1047
      data_needed:
        - Process command-line telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Known technique for lateral movement.
---

Windows Management Instrumentation (WMI) is a powerful administrative feature that can be abused by adversaries for lateral movement, remote code execution, and persistent control within a Windows network. Specifically, the command-line utility `wmic.exe` can be used to interface with the WMI service and invoke the `Win32_Process` class to start processes on remote systems. 

This activity is a hallmark of sophisticated actor behavior, frequently identified in ransomware deployments, state-sponsored cyber operations, and Red Team exercises. By utilizing flags such as `/node` to specify a target machine, combined with the `process call create` verb, attackers can execute arbitrary payloads without the need for traditional remote access software. Defenders should focus on process telemetry, specifically identifying `wmic.exe` command-line arguments that indicate cross-system execution requests.

## Attack Chain

1. Attacker achieves initial access to a compromised host within the victim network.
2. Attacker performs internal reconnaissance to identify high-value targets or domain credentials.
3. Attacker uses compromised credentials to attempt lateral movement via WMI.
4. Attacker executes `wmic.exe` with `/node:<Target_IP>` to connect to the remote host.
5. Attacker passes the `process call create` parameters to the WMI service on the target.
6. The remote WMI service spawns the requested process (e.g., a reverse shell or beacon) under the SYSTEM or user context.
7. Attacker establishes a remote session on the target host for further post-exploitation and lateral spread.

## Impact

Abuse of WMI enables attackers to propagate malware, deploy ransomware payloads across multiple hosts, and maintain stealthy administrative control. Successful exploitation allows for arbitrary code execution, potentially leading to widespread data exfiltration, service disruption, and total system compromise within the affected network segments.

## Recommendation

* Deploy the Sigma rule below to monitor for suspicious command-line execution patterns associated with WMI remote process creation.
* Monitor for any usage of `wmic.exe` with the `/node` parameter; while some administrative tools may utilize this, it is considered anomalous in most mature enterprise environments.
* Ensure Sysmon Event ID 1 or Windows Security Event ID 4688 is ingested, ensuring complete command-line strings are captured for analysis.
* Establish a baseline for legitimate administrative WMI usage to reduce false positives during alert tuning.
