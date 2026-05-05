---
title: Windows Audit Policy Disabled via Legacy Auditpol
slug: 2024-01-auditpol-disable
description: Adversaries may disable Windows audit policies using the legacy auditpol.exe utility to evade detection by limiting the data available for security monitoring and incident response.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - auditpol
  - defense-evasion
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Windows
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.microsoft.com/en-us/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/
  - https://www.cybereason.com/blog/research/prometei-botnet-exploiting-microsoft-exchange-vulnerabilities
  - https://attack.mitre.org/techniques/T1562/002/
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-set
rules:
  - title: Detect Auditpol Usage
    description: Detects the execution of auditpol.exe with parameters that disable auditing.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Auditpol via WMI
    description: Detects the execution of auditpol.exe via WMI
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1047
      - T1562.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The execution of the legacy `auditpol.exe` utility, included with the Windows 2000 Resource Kit Tools, is used to disable specific logging categories from the audit policy. This technique is often employed by adversaries and Red Teams to evade detection by reducing the amount of data available for security monitoring and incident response. This behavior, if confirmed malicious, can enable attackers to bypass defenses, potentially leading to full machine compromise or lateral movement. The use of `auditpol.exe` with the `/disable` argument, or category flags followed by the `none` option, indicates a deliberate attempt to tamper with system auditing configurations.

## Attack Chain

1.  An attacker gains initial access to a compromised system through various means.
2.  The attacker executes `auditpol.exe` from the command line.
3.  The attacker uses the `/disable` parameter to disable auditing globally.
4.  Alternatively, the attacker uses category-specific flags (e.g., `/system`, `/logon`, `/object`) with the `none` option to disable auditing for those specific categories.
5.  The command is executed with sufficient privileges to modify the audit policy.
6.  Windows processes the command and updates the system's audit policy accordingly.
7.  Logging for the specified categories is disabled, reducing the visibility of attacker activity.
8.  The attacker proceeds with further malicious actions, knowing that their activities are less likely to be detected due to the reduced audit logging.

## Impact

Successful execution of this attack can lead to significant gaps in security monitoring. With auditing disabled, security teams lose visibility into critical system events, making it more difficult to detect and respond to ongoing attacks. Attackers can exploit this lack of visibility to move laterally within the network, escalate privileges, and exfiltrate sensitive data without being detected.

## Recommendation

*   Enable Sysmon process creation logging (Event ID 1) and Windows Security Event Log (4688) to detect the execution of `auditpol.exe` with suspicious command-line arguments.
*   Deploy the Sigma rule `Detect Auditpol Usage` to your SIEM and tune for your environment.
*   Review and harden audit policies to prevent unauthorized modifications, as detailed in the Microsoft documentation.
*   Monitor process execution for processes disabling audit logs.
