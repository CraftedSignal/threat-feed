---
title: Disable Windows Event and Security Logs Using Built-in Tools
slug: 2024-01-02-disable-windows-logs
description: Attackers may attempt to disable Windows event logging to evade detection by using built-in tools like logman, PowerShell, and auditpol.
date: "2024-01-02T12:00:00Z"
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
products:
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
  - https://attack.mitre.org/techniques/T1070/
  - https://attack.mitre.org/techniques/T1070/001/
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/002/
  - https://attack.mitre.org/techniques/T1562/006/
rules:
  - title: Disable Windows Event Logs via Logman
    description: Detects attempts to disable Windows Event Logs using logman.exe.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
      - T1562.002
    data_sources:
      - process_creation
      - windows
  - title: Disable Windows Event Logs via PowerShell
    description: Detects attempts to disable Windows Event Logs using PowerShell.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
      - T1562.002
    data_sources:
      - process_creation
      - windows
  - title: Disable Windows Event Logs via Auditpol
    description: Detects attempts to disable Windows Event Logs using auditpol.exe.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
      - T1562.002
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Attackers may disable Windows event logs to evade detection and hide their activities. This involves using built-in Windows utilities such as `logman.exe`, PowerShell (`powershell.exe`, `pwsh.exe`, `powershell_ise.exe`), and `auditpol.exe` to stop or disable the EventLog service or specific event logs. Disabling logging can prevent defenders from detecting malicious activity and hinder incident response efforts. This activity is usually associated with post-exploitation behavior. The tools mentioned are legitimate Windows binaries, making it harder to distinguish malicious use from legitimate administration. This rule detects the abuse of these tools.

## Attack Chain

1.  The attacker gains initial access to the system (e.g., via phishing or exploit).
2.  The attacker executes `powershell.exe` to disable the EventLog service using the `Set-Service` cmdlet with the `Disabled` parameter.
3.  Alternatively, the attacker executes `logman.exe` to stop or delete specific EventLog traces, such as `EventLog-*`.
4.  The attacker may use `auditpol.exe` with the `/success:disable` argument to disable auditing policies.
5.  The attacker performs malicious activities, such as lateral movement, privilege escalation, or data exfiltration.
6.  The attacker attempts to remove traces of their activity by deleting or disabling specific event logs using `logman.exe`.
7.  The attacker leverages PowerShell to further impair defenses by disabling security features.
8.  The attacker achieves their objective (e.g., data theft, system compromise) without being detected due to disabled logging.

## Impact

Successful disabling of Windows event logs can severely hinder incident response and forensic investigations. It allows attackers to operate undetected, making it difficult to identify the scope of the compromise, the attacker's actions, and the data that was accessed or stolen. Without logs, security teams lose visibility into the attacker's activities, increasing dwell time and the potential for significant damage. Depending on the targeted system, impact could range from disabling logging on a single workstation to a domain controller affecting a whole environment.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM to detect attempts to disable Windows event logging. Tune for your environment (see "Disable Windows Event and Security Logs Using Built-in Tools" rules).
*   Monitor process creation events for the execution of `logman.exe`, `powershell.exe`, `pwsh.exe`, `powershell_ise.exe`, and `auditpol.exe` with arguments related to disabling event logs (process_creation logsource).
*   Investigate any detected instances of these commands to determine if they are legitimate or malicious ("Disable Windows Event and Security Logs Using Built-in Tools" rules).
*   Implement strict access controls and auditing policies to limit who can modify event logging configurations.
