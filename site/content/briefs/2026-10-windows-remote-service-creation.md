---
title: Detection of Remote Windows Service Creation via sc.exe
slug: 2026-10-windows-remote-service-creation
description: Adversaries utilize the sc.exe utility to create services on remote Windows endpoints to establish persistence, escalate privileges, or facilitate lateral movement.
date: "2026-10-12T18:20:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - persistence
  - privilege-escalation
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: Adversaries frequently leverage remote service creation to achieve persistence, escalate privileges, or facilitate lateral movement across a network.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: Adversaries frequently leverage remote service creation to achieve persistence, escalate privileges, or facilitate lateral movement across a network.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: Adversaries frequently leverage remote service creation to achieve persistence, escalate privileges, or facilitate lateral movement across a network.
    confidence_band: high
rules:
  - title: Detect Remote Windows Service Creation via sc.exe
    description: Detects the creation of a new service on a remote endpoint by monitoring sc.exe command-line arguments for remote host syntax.
    platform: sigma
    severity: medium
    tactics:
      - lateral-movement
      - persistence
      - privilege-escalation
    techniques:
      - T1543.003
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
    - action: Deploy the Sigma rule to detect remote service creation via sc.exe
      owner: Detection Engineering
      due: 48h
      evidence: Source documentation for T1543.003 coverage.
  hunt_leads:
    - lead: Search for sc.exe process execution containing remote server syntax
      technique_id: T1543.003
      data_needed:
        - Endpoint process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Analytic story documentation for lateral movement.
---

This threat brief focuses on the exploitation of the Windows Service Control utility (sc.exe) for unauthorized remote service creation. This technique is frequently observed in lateral movement and persistence phases of cyberattacks, including deployments of BlackSuit ransomware. By invoking `sc.exe` with a remote host specification (e.g., `sc \\<remote_host> create ...`), an attacker can execute arbitrary binaries as a service, typically running with SYSTEM privileges. Defenders should monitor for process creation events where `sc.exe` is launched with command-line arguments containing remote host indicators (backslashes or computer names). This activity is critical to monitor as it serves as a high-fidelity indicator of potential compromise when originated from non-administrative or unexpected parent processes.

## Attack Chain

1. Attacker gains initial access to a compromised workstation within the target network.
2. Attacker performs internal reconnaissance to identify remote high-value targets.
3. Attacker uses compromised credentials to initiate a session with a target host using SMB or RPC.
4. Attacker executes `sc.exe \\<target_host> create <service_name> binpath= "<path_to_malicious_binary>"` from the initial access point.
5. The target host's Service Control Manager (SCM) registers the new service entry.
6. The SCM logs the event (Event ID 7045) locally on the target system.
7. Attacker executes `sc.exe \\<target_host> start <service_name>` to trigger the malicious payload.
8. The malicious binary executes as a SYSTEM service, granting the attacker persistent remote code execution.

## Impact

Successful exploitation allows an attacker to maintain persistent, high-privilege access across the network. This technique has been documented as part of the operational lifecycle for ransomware groups, including BlackSuit. Unauthorized service creation can lead to credential dumping, full system compromise, and further lateral movement. If not detected, attackers can rotate persistence mechanisms or deploy additional toolsets, such as remote access trojans (RATs) or custom backdoors, significantly increasing the recovery timeline following an incident.

## Recommendation

* Deploy the provided Sigma rule to detect `sc.exe` execution patterns targeting remote systems across the environment.
* Enable comprehensive command-line logging (Event ID 4688 or Sysmon Event ID 1) to capture the arguments passed to `sc.exe`.
* Baseline administrative use of `sc.exe` to filter out legitimate software management tools and minimize noise for the security operations center.
* Monitor for Windows Event ID 7045 to capture service creation events, regardless of the binary name, for additional coverage.
