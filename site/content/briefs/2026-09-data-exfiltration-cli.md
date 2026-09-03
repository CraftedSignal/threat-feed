---
title: Detection of Data Exfiltration via Native Windows Command-Line Utilities
slug: 2026-09-data-exfiltration-cli
description: Adversaries are leveraging legitimate Windows command-line tools such as PowerShell, curl, and wget to collect system information and exfiltrate data via HTTP POST requests.
date: "2026-09-03T12:44:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - data-exfiltration
  - command-line
  - living-off-the-land
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Detects the use of various CLI utilities exfiltrating data via web requests.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_susp_data_exfiltration_via_cli.yml
  - https://www.sentinelone.com/blog/living-off-windows-defender-lockbit-ransomware-sideloads-cobalt-strike-through-microsoft-security-tool/
rules:
  - title: Potential Data Exfiltration Activity Via CommandLine Tools
    description: Detects the use of various CLI utilities (PowerShell, curl, wget) executing reconnaissance commands combined with HTTP POST requests to exfiltrate data.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
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
    - action: Deploy the provided Sigma rule to SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided in source.
  hunt_leads:
    - lead: Search logs for command line arguments containing both reconnaissance terms and POST requests.
      technique_id: T1059.001
      data_needed:
        - Process Creation events with full command line.
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly defines these patterns.
  mitigation_plan:
    - priority: medium_term
      action: Restrict command line utility execution for non-admin accounts.
      owner: IT Operations
      evidence: General security best practice.
---

Security researchers have identified a persistent technique where threat actors utilize native Windows binaries to perform reconnaissance and exfiltrate sensitive data. Attackers frequently employ tools like PowerShell, cmd.exe, curl.exe, and wget.exe to bypass traditional security controls. By chaining system enumeration commands (e.g., whoami, systeminfo, netstat) with HTTP request modules, attackers can capture environmental data and immediately transmit it to remote command-and-control (C2) infrastructure. This technique allows for low-footprint operations, as the activity mimics legitimate administrative scripts and utility execution. Defenders must monitor process creation events that exhibit the specific pattern of system data collection followed by a network-based file transfer or post request.

## Attack Chain

1. An attacker gains initial execution on a target Windows endpoint.
2. The attacker enumerates system information using commands such as 'whoami', 'hostname', or 'systeminfo'.
3. The attacker collects network configuration details via 'ipconfig' or 'netstat'.
4. System data is gathered or redirected to a staging location (e.g., 'type C:\sensitive.txt > C:\temp\data.tmp').
5. The attacker invokes a built-in utility like PowerShell ('Invoke-RestMethod'), 'curl', or 'wget'.
6. The utility is instructed to perform an HTTP POST request to an external C2 server.
7. The collected data is transmitted in the body or payload of the HTTP request, completing the exfiltration.

## Impact

Successful exploitation of this technique leads to unauthorized data exfiltration, loss of intellectual property, and compromise of sensitive system information. Because these activities leverage built-in, trusted binaries, they can significantly increase the duration of an undetected compromise, allowing attackers to persist and exfiltrate data incrementally without triggering traditional signature-based malware alerts.

## Recommendation

1. Deploy the Sigma rules below to your SIEM to monitor for combinations of reconnaissance commands and network-capable binary execution.
2. Enable Sysmon Event ID 1 (Process Creation) to capture detailed CommandLines, which are essential for identifying the arguments (e.g., -uri, -method, POST) required for these detections.
3. Establish a baseline for administrative script activity to tune out legitimate IT management tools that utilize these same utilities.
4. Implement EDR blocks for unauthorized usage of 'curl.exe' or 'wget.exe' if these utilities are not required for standard business operations.
