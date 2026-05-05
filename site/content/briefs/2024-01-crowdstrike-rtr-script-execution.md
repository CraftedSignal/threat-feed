---
title: Crowdstrike RTR Script Execution via PowerShell
slug: 2024-01-crowdstrike-rtr-script-execution
description: Detection of PowerShell execution initiated via Crowdstrike Real Time Response (RTR) 'runscript' command, potentially indicating malicious actors leveraging compromised Crowdstrike Dashboard access to execute commands on remote hosts using encoded commands.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - living-off-the-land
  - rtr
  - script-execution
vendors:
  - Splunk
  - CrowdStrike
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Crowdstrike Dashboard
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/unc3944-targets-saas-applications
rules:
  - title: Detect Crowdstrike RTR PowerShell EncodedCommand Execution
    description: Detects PowerShell execution with encoded commands initiated by dllhost.exe, indicative of Crowdstrike RTR script execution abuse.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Crowdstrike RTR PowerShell EncodedCommand Execution - Alternate
    description: Detects PowerShell execution with encoded commands initiated by dllhost.exe, indicative of Crowdstrike RTR script execution abuse -Alternate selection criteria
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief addresses the abuse of Crowdstrike Real Time Response (RTR) functionality to execute arbitrary commands on managed hosts. Attackers with access to a Crowdstrike Dashboard can use the "runscript" command to execute scripts, often PowerShell, on remote systems. This is particularly concerning because it allows attackers to leverage a trusted platform for malicious purposes, potentially bypassing traditional security controls. The encoded commands within PowerShell obfuscate the attacker's actions, making detection more challenging. This technique has been observed in past campaigns where threat actors target SaaS applications, highlighting the potential for significant impact on organizations relying on these services.

## Attack Chain

1.  Attacker gains unauthorized access to the Crowdstrike Dashboard.
2.  Attacker uses the RTR "runscript" command to initiate a PowerShell script execution on a target host.
3.  The RTR process spawns `dllhost.exe` to execute the script.
4.  `dllhost.exe` initiates `powershell.exe` with encoded command parameters (`-EncodedCommand`).
5.  PowerShell executes the attacker-controlled, obfuscated script.
6.  The script performs malicious activities such as reconnaissance, lateral movement, or data exfiltration.
7.  Results of the script execution may be returned to the attacker via command and control channels.
8.  Attacker achieves their final objective, such as data theft, system compromise, or ransomware deployment.

## Impact

Successful exploitation can lead to complete compromise of targeted systems. An attacker with RTR access can use this technique to bypass normal endpoint security controls. This can result in data breaches, financial losses, and reputational damage. The impact is amplified by the trust relationship between Crowdstrike and its managed endpoints, making detection and prevention more difficult.

## Recommendation

*   Deploy the Sigma rule `Detect Crowdstrike RTR PowerShell EncodedCommand Execution` to identify suspicious PowerShell executions originating from Crowdstrike RTR.
*   Monitor process creation events (Sysmon EventID 1) and filter for PowerShell processes with encoded commands (`-EncodedCommand`) where the parent process is `dllhost.exe`.
*   Review and restrict Crowdstrike Dashboard access to only authorized personnel to prevent unauthorized use of RTR.
*   Implement multi-factor authentication (MFA) for all Crowdstrike Dashboard accounts.
*   Implement the Sigma rule `Detect Crowdstrike RTR PowerShell EncodedCommand Execution - Alternate`.
