---
title: Disable Windows Event and Security Logs Using Built-in Tools
slug: 2024-01-disable-windows-logs
description: Attackers attempt to disable Windows Event and Security Logs using logman, PowerShell, or auditpol to evade detection and cover their tracks.
date: "2024-01-04T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows
  - eventlog
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
  - Crowdstrike
products:
  - Microsoft Defender XDR
  - Elastic Defend
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/logman
  - https://medium.com/palantir/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63
rules:
  - title: Detect Disabling Windows Event Logs via Logman
    description: Detects the use of logman.exe to stop or delete EventLog traces, which is often used to evade detection.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Disabling Windows Event Logs via PowerShell
    description: Detects the use of PowerShell to disable the EventLog service, a technique used for defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1059.001
      - T1562.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Disabling Windows Event Logs via Auditpol
    description: Detects the use of Auditpol to disable auditing, which is used for defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.002
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Attackers often disable Windows Event and Security Logs to evade detection on compromised systems. This activity involves tampering with, clearing, and deleting event log data to break SIEM detections, cover their tracks, and slow down incident response. The methods employed include using the `logman` utility, PowerShell commands to disable the EventLog service, or `auditpol` to disable auditing. These actions are typically performed after initial access and privilege escalation to hinder forensic investigations and maintain persistence within the environment. Defenders should monitor for these specific tools and command-line arguments to identify potential attempts to disable logging.

## Attack Chain

1.  The attacker gains initial access to the system, possibly through phishing or exploiting a vulnerability.
2.  The attacker escalates privileges to administrator level to gain the necessary permissions to modify event logging settings.
3.  The attacker uses `logman.exe` with arguments to stop or delete EventLog traces (e.g., `logman.exe stop EventLog-*`, `logman.exe delete EventLog-*`).
4.  Alternatively, the attacker uses PowerShell with `Set-Service` cmdlet to disable the EventLog service (e.g., `powershell.exe Set-Service EventLog -StartupType Disabled`).
5.  The attacker can also use `auditpol.exe` to disable auditing policies, preventing future events from being logged (e.g., `auditpol.exe /success:disable`).
6.  After disabling logging, the attacker performs malicious activities such as lateral movement, data exfiltration, or malware deployment, with a reduced risk of detection.
7. The attacker removes traces of their activity from other logs if possible.
8. The attacker maintains persistence and continues to exploit the compromised environment.

## Impact

Successful disabling of Windows Event and Security Logs can severely hinder incident response and forensic investigations. The absence of log data makes it difficult to detect ongoing malicious activity, understand the scope of the compromise, and attribute the attack. This can lead to prolonged dwell time for attackers, increased data exfiltration, and greater overall damage to the organization.

## Recommendation

*   Deploy the Sigma rule "Disable Windows Event and Security Logs Using Built-in Tools" to your SIEM to detect the execution of `logman.exe`, PowerShell, and `auditpol.exe` with specific arguments related to disabling event logs.
*   Monitor process creation events for `logman.exe`, `powershell.exe`, `pwsh.exe`, `powershell_ise.exe`, and `auditpol.exe` with command-line arguments that indicate an attempt to disable event logging.
*   Enable Sysmon process creation logging to capture detailed command-line arguments for process monitoring.
*   Regularly review and audit Group Policy settings related to event logging to prevent unauthorized modifications.
*   Monitor for changes to the EventLog service configuration, including startup type and status, using system monitoring tools.
