---
brief_id: brief-2026-11-25-wsl-binary-hijack
event_id: brief-2026-11-25-wsl-binary-hijack
revision: 1
activity_at: "2026-11-25T16:33:55Z"
title: Windows Subsystem for Linux (WSL) Binary Hijack via InstallLocation Registry Modification
slug: 2026-11-wsl-binary-hijack
description: Attackers can achieve stealthy execution by modifying the WSL InstallLocation registry key, forcing the legitimate System32 wsl.exe stub to proxy execution to a malicious wsl.exe binary.
date: "2026-11-25T16:33:55Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Technical verification of the detection rule logic suggests it reliably identifies the specified proxy execution pattern.
tags:
  - defense-evasion
  - living-off-the-land
  - proxy-execution
affected_os:
  - Windows 10
  - Windows 11
  - Windows Server 2019
  - Windows Server 2022
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036.005
    technique_name: Match Legitimate Name or Location
    evidence: An attacker who modifies InstallLocation to a controlled path causes the stub to transparently proxy execution to a malicious payload, which then appears as a wsl.exe child of the legitimate System32 stub.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: When WSL or bash is invoked, the System32 stub (wsl.exe) looks up the InstallLocation registry key and executes the wsl.exe found there.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_wsl_binary_hijack_execution.yml
  - https://web.archive.org/web/20260718025639/https://cardinalops.com/blog/bash-and-switch-hijacking-via-windows-subsystem-for-linux/
rules:
  - title: Detect Suspicious WSL Binary Hijack Execution
    description: Detects the legitimate C:\Windows\System32\wsl.exe spawning a child wsl.exe process from an unexpected location, indicating potential registry-based hijacking.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1036.005
      - T1218
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
    - action: Deploy the detection rule for wsl.exe parent-child relationship monitoring to SIEM/EDR.
      owner: Detection Engineering
      due: 48h
      evidence: 'Sigma rule: proc_creation_win_wsl_binary_hijack_execution'
  hunt_leads:
    - lead: Identify registry modifications to HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss or user-specific WSL registry paths.
      technique_id: T1547
      data_needed:
        - Registry set/delete events (Sysmon Event ID 12/13)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The attack relies on registry key manipulation to redirect execution.
---

## Overview

Adversaries can perform a proxy execution attack by manipulating the Windows registry to hijack the execution flow of the Windows Subsystem for Linux (WSL). When users or automated processes invoke the legitimate wsl.exe residing in C:\Windows\System32, the binary queries the registry key 'InstallLocation' to determine the path of the actual WSL installation. By modifying this registry key to point to an attacker-controlled directory, the wsl.exe stub will transparently launch a malicious binary named 'wsl.exe' instead of the legitimate environment, allowing attackers to execute code while maintaining the appearance of a legitimate WSL process.

## Attack Chain

1. Attacker gains administrative or sufficient user privileges to modify registry keys.
2. Attacker places a malicious wsl.exe binary into a non-standard directory.
3. Attacker updates the 'InstallLocation' registry key associated with WSL to the path of the malicious binary.
4. A user or process executes the legitimate C:\Windows\System32\wsl.exe.
5. The System32 stub reads the compromised 'InstallLocation' registry value.
6. The System32 stub executes the malicious wsl.exe binary as a child process, proxying the requested action to the payload.

## Recommendation

Deploy the provided detection rule to monitor for wsl.exe processes originating from unexpected paths. Additionally, audit the registry for unexpected modifications to the InstallLocation keys associated with WSL. Restrict write access to registry locations related to WSL configuration to only authorized system administrators.

## Impact

This technique enables stealthy code execution and persistence, potentially bypassing security controls that white-list the legitimate System32 wsl.exe while failing to inspect its child processes or non-standard WSL installation paths.
