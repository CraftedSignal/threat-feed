---
title: Suspicious Modification of WSL InstallLocation Registry Key
slug: 2026-10-wsl-registry-hijack
description: Adversaries manipulate the WSL 'InstallLocation' registry key to redirect the Windows Subsystem for Linux to a malicious binary, facilitating persistence and stealthy code execution.
date: "2026-10-02T10:12:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - defense-impairment
  - wsl
  - registry
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
    evidence: Manual use of reg.exe or PowerShell to set this value strongly indicates an attempt to redirect WSL execution to a malicious binary.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: Adversaries manipulate the WSL 'InstallLocation' registry key to redirect the Windows Subsystem for Linux to a malicious binary.
    confidence_band: high
rules:
  - title: Detect Suspicious WSL InstallLocation Registry Key Modification
    description: Detects the use of reg.exe or PowerShell to modify the WSL InstallLocation registry key via command-line arguments.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1112
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
    - action: Deploy the Sigma detection rule to identify unauthorized registry modifications.
      owner: Detection Engineering
      due: 24h
  hunt_leads:
    - lead: Search logs for process creation events involving reg.exe, powershell.exe, or pwsh.exe where CommandLine contains 'Lxss' and 'InstallLocation'.
      technique_id: T1112
      data_needed:
        - Process creation telemetry
      priority: high
      confidence: high
      disposition: hunt_now
  mitigation_plan:
    - priority: medium_term
      action: Implement strict Registry Access Control Lists (ACLs) on the WSL registry hive to prevent unauthorized modifications.
      owner: IT Operations
      addresses: T1112
---

Adversaries are targeting the Windows Subsystem for Linux (WSL) by manually modifying the 'InstallLocation' registry key. This registry value, located under the 'Lxss\MSI' hive, normally dictates the execution path for WSL environments. By altering this path, an attacker can trick the system into launching a malicious executable instead of the legitimate WSL runtime whenever a user initiates a bash or wsl command. This technique, documented in several security research reports, allows for persistent and stealthy code execution on Windows systems. Because legitimate updates to this key are strictly handled by the Windows Installer (msiexec.exe), any direct modification using command-line tools like 'reg.exe' or PowerShell is a strong indicator of malicious intent and unauthorized system configuration.

## Attack Chain

1. Attacker gains initial access to the target Windows system through phishing or exploit.
2. Attacker performs local reconnaissance to identify installed WSL distributions.
3. Attacker identifies the specific registry path 'HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss' or similar.
4. Attacker prepares a malicious executable intended to masquerade as the WSL runtime.
5. Attacker executes 'reg.exe' or a PowerShell command (e.g., 'Set-ItemProperty') to update the 'InstallLocation' registry key.
6. Attacker points the registry key value to the path containing the malicious binary.
7. Attacker triggers a WSL session, causing the malicious binary to execute with the privileges of the invoking user.
8. Final objective is achieved, such as maintaining persistence, lateral movement, or executing arbitrary payloads.

## Impact

Successful manipulation of the WSL 'InstallLocation' key allows for stealthy, high-privilege code execution and persistent access. This technique has been observed in various malware campaigns to bypass traditional security controls that may not monitor the integrity of WSL configuration paths, potentially compromising sensitive data and user accounts across multiple enterprise environments.

## Recommendation

1. Deploy the Sigma rule provided in this brief to detect manual registry modifications targeting the 'Lxss\MSI' registry hive.
2. Baseline and monitor registry modifications for keys related to WSL distribution configurations, focusing on 'InstallLocation' values.
3. Restrict administrative privileges to prevent unauthorized use of 'reg.exe' and PowerShell for system configuration changes.
4. Enable and monitor Sysmon Event ID 12 and 13 for registry modifications to critical WSL keys.
