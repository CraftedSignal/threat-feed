---
title: Suspicious WSL Binary Hijack via Proxy Execution
slug: 2026-10-wsl-hijack
description: Adversaries can achieve stealthy code execution by modifying the Windows WSL InstallLocation registry key to redirect the System32 wsl.exe stub to a malicious binary.
date: "2026-10-02T10:12:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - stealth
  - persistence
  - windows
  - wsl
affected_os:
  - Windows 10
  - Windows 11
  - Windows Server 2019
  - Windows Server 2022
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: An attacker who modifies InstallLocation to a controlled path causes the stub to transparently proxy execution to a malicious payload.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The System32 stub (wsl.exe) looks up the InstallLocation registry key and executes the wsl.exe found there.
    confidence_band: high
references:
  - https://cardinalops.com/blog/bash-and-switch-hijacking-via-windows-subsystem-for-linux/
  - https://blog.qualys.com/vulnerabilities-threat-research/2022/04/20/implications-of-windows-subsystem-for-linux-for-adversaries-defenders-part-2/
  - https://www.bleepingcomputer.com/news/security/new-malware-uses-windows-subsystem-for-linux-for-stealthy-attacks/
rules:
  - title: Suspicious WSL Binary Hijack via Proxy Execution
    description: Detects C:\Windows\System32\wsl.exe spawning a child wsl.exe process from outside the legitimate WSL install locations.
    platform: sigma
    severity: high
    tactics:
      - stealth
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
    - action: Deploy the Sigma rule for WSL process creation monitoring.
      owner: Detection Engineering
      due: 48h
      evidence: Sigma rule provided in source.
  hunt_leads:
    - lead: Search for registry keys under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss containing paths outside of standard install locations.
      technique_id: T1546
      data_needed:
        - Registry modification logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source documentation on InstallLocation modification.
---

Adversaries are leveraging a proxy execution technique involving the Windows Subsystem for Linux (WSL) to achieve stealthy code execution. The legitimate WSL stub located at C:\Windows\System32\wsl.exe is responsible for locating and executing the WSL environment. During this process, the stub consults a specific registry key named InstallLocation to determine where the actual wsl.exe binary resides. By modifying this registry key to point to a user-controlled path, an attacker can force the system to execute a malicious wsl.exe binary instead of the legitimate one. Because the initial process (the System32 stub) is trusted, the execution of the child process may bypass certain security controls or evade detection by appearing as a legitimate child process of the WSL subsystem. This technique has been documented in various security research reports highlighting how WSL can be abused for persistent and stealthy post-exploitation activities on Windows hosts.

## Attack Chain

1. Attacker gains sufficient privileges to modify the Windows registry (e.g., via previous foothold or local privilege escalation).
2. Attacker writes a malicious binary, named wsl.exe, to a directory under their control (e.g., C:\ProgramData\ or a user temp folder).
3. Attacker modifies the registry key HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss or related InstallLocation entries to point to the malicious binary's path.
4. User or system triggers the legitimate WSL stub by invoking C:\Windows\System32\wsl.exe.
5. The System32 wsl.exe reads the registry key, identifies the attacker-controlled path, and initiates the malicious wsl.exe.
6. The malicious wsl.exe process executes, inheriting the context of the parent, potentially launching further stages or C2 beacons.
7. Final objective is achieved, such as persistence, privilege escalation, or exfiltration, while the execution appears disguised as a WSL component.

## Impact

Successful exploitation allows attackers to execute arbitrary code with the context of the user triggering the process, potentially bypassing application allowlisting that trusts the legitimate System32 wsl.exe. This technique provides a mechanism for post-exploitation stealth and persistence across various Windows environments where WSL is enabled, affecting both desktop and server instances.

## Recommendation

* Deploy the provided Sigma rule to detect wsl.exe child processes spawned from non-standard locations.
* Implement Registry integrity monitoring for the Lxss registry keys to detect unauthorized changes to the InstallLocation values.
* Audit authorized WSL installation paths across the fleet to define a strict allowlist for legitimate wsl.exe binaries.
* Monitor for unexpected registry modifications (Registry_Set events) targeting the Lxss configuration.
