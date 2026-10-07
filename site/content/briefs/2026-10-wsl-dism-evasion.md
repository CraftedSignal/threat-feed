---
title: Defense Evasion via WSL Enablement using DISM
slug: 2026-10-wsl-dism-evasion
description: Adversaries may attempt to enable the Windows Subsystem for Linux (WSL) using the legitimate DISM utility to facilitate the execution of Linux-based tools and bypass Windows-specific security controls.
date: "2026-10-07T16:41:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - wsl
  - dism
vendors:
  - Microsoft
products:
  - Windows Subsystem for Linux
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: Adversaries may enable and use WSL for Linux to avoid detection.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_wsl_enabled_via_dism.toml
  - https://attack.mitre.org/techniques/T1202/
rules:
  - title: Detect Windows Subsystem for Linux Enabled via Dism Utility
    description: Detects attempts to enable the Windows Subsystem for Linux using Microsoft Dism utility. Adversaries may enable and use WSL for Linux to avoid detection.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1202
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
    - action: Deploy Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source provides logic for detecting DISM enablement of WSL
  hunt_leads:
    - lead: Search historic logs for Dism.exe executing with WSL-related arguments
      technique_id: T1202
      data_needed:
        - Process creation logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The activity is a known technique for defense evasion
  mitigation_plan:
    - priority: medium_term
      action: Restrict administrative rights for DISM to authorized personnel
      owner: IT Operations
      addresses: T1202
      evidence: DISM is an administrative tool that can alter OS configuration
---

The Windows Subsystem for Linux (WSL) allows users to run Linux distributions and command-line tools natively on Windows. Adversaries often abuse this feature to evade security protections, as Linux-based tooling and bash environments may not be monitored by security tools configured strictly for Windows binaries. This technique involves using the built-in Deployment Image Servicing and Management (DISM) utility to programmatically enable the WSL feature on a compromised host. By transitioning the environment to include Linux capabilities, attackers gain a platform to execute malicious scripts, deploy Linux-based malware, or perform post-exploitation tasks while minimizing their footprint on the Windows host's primary security stack. Monitoring for unauthorized use of DISM to modify Windows features is a critical component of endpoint security.

## Attack Chain

1. Attacker gains initial access to the Windows host through phishing or exploit.
2. Attacker identifies that WSL is not enabled, limiting their ability to execute custom Linux payloads.
3. Attacker executes `Dism.exe` with administrative privileges.
4. Attacker supplies the `/Enable-Feature` argument targeting `Microsoft-Windows-Subsystem-Linux`.
5. The OS enables the subsystem, potentially requiring a system reboot or further configuration.
6. Attacker downloads or executes Linux-native payloads or shells (e.g., bash).
7. Attacker performs malicious activity, such as exfiltration or lateral movement, using the Linux environment.

## Impact

Successful exploitation allows an attacker to operate within a Linux environment on a Windows host, effectively bypassing security controls that lack visibility into Linux-native execution or shell activity. This can lead to persistent access, enhanced capability to deploy complex cross-platform malware, and increased difficulty for incident responders to perform forensic analysis, as malicious activity may be logged in Linux-specific locations rather than standard Windows event logs.

## Recommendation

Prioritize monitoring of the `Dism.exe` utility and establish a baseline for authorized feature changes in the environment.

- Deploy the provided Sigma rule to detect `Dism.exe` invocations that enable WSL.
- Review administrative activity logs for `Dism.exe` execution across all endpoints.
- Establish a process for identifying and authorizing WSL usage within the enterprise.
- Enable Sysmon process-creation logging (Event ID 1) to ensure the detection of process command-line arguments.
