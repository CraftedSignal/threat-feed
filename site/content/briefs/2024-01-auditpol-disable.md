---
title: Windows Audit Policy Auditing Option Disabled via Auditpol
slug: 2024-01-auditpol-disable
description: Adversaries may disable Windows audit policy settings using auditpol.exe to evade detection by limiting audit data.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - audit-policy
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
  - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/262a2bed-93d4-4c04-abec-cf06e9ec72fd
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-set
rules:
  - title: Auditpol Disable Auditing Option
    description: Detects the use of auditpol.exe to disable auditing options.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.002
    data_sources:
      - process_creation
      - windows
  - title: Auditpol Disable Auditing Option via Cmd
    description: Detects the use of auditpol.exe being run from cmd to disable auditing options.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief examines the abuse of `auditpol.exe`, a legitimate Windows command-line tool, to disable audit policy settings. Attackers and red teams may leverage this technique to evade detection by reducing the volume of security logs generated, specifically those that might reveal malicious activity. The activity involves executing `auditpol.exe` with parameters like `/set`, `/option`, and `/value:disable` to target critical auditing options such as FullPrivilegeAuditing, AuditBaseObjects, and AuditBaseDirectories. Detecting this behavior is important because successful execution can lead to significant gaps in security monitoring, enabling attackers to operate with reduced visibility, increasing the likelihood of successful compromise and lateral movement.

## Attack Chain

1. An attacker gains initial access to a Windows system, potentially through phishing or exploiting a vulnerability.
2. The attacker elevates privileges to an administrator account to execute `auditpol.exe`.
3. The attacker executes `auditpol.exe` with the `/set` parameter to modify audit policy settings.
4. The attacker uses the `/option` parameter to specify which audit settings to modify, targeting options like `FullPrivilegeAuditing`, `AuditBaseObjects`, or `AuditBaseDirectories`.
5. The attacker employs the `/value:disable` parameter to disable the specified audit settings.
6. The command `auditpol.exe /set /option:FullPrivilegeAuditing /value:disable` is executed, which disables the auditing of full privilege usage.
7. With auditing disabled, attacker activities are less likely to be logged and detected.
8. The attacker proceeds with malicious activities, such as lateral movement, data exfiltration, or deploying ransomware, under reduced scrutiny.

## Impact

Disabling audit policies can significantly reduce the visibility of malicious activities within an environment. If successful, attackers can bypass existing security controls that rely on Windows event logs for detection and alerting. This can lead to delayed incident response, increased dwell time, and greater damage from security breaches. Organizations relying on default Windows auditing configurations are particularly vulnerable.

## Recommendation

*   Monitor process creation events for `auditpol.exe` executions with command-line arguments containing `/set`, `/option`, and `/value:disable`, especially when targeting `FullPrivilegeAuditing`, `AuditBaseObjects`, or `AuditBaseDirectories`. Implement the provided Sigma rules to detect this activity.
*   Ensure proper logging configuration for process creation (Event ID 4688 or Sysmon Event ID 1) to capture the necessary command-line arguments for detection.
*   Regularly review and validate audit policy settings using Group Policy or other configuration management tools to prevent unauthorized modifications.
*   Ingest and normalize endpoint process execution logs using the Splunk Common Information Model (CIM) to facilitate the implementation of the provided Sigma rules.
