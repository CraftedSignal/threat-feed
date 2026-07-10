---
title: Windows Audit Policy Sub-Category Disabled
slug: 2024-01-audit-policy-disabled
description: This rule detects attempts to disable auditing for security-sensitive audit policy sub-categories on Windows systems, often done by attackers to evade detection and forensic analysis.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense_evasion
  - windows
  - audit_policy
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
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4719
  - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d
rules:
  - title: Detect Audit Policy Sub-Category Disabled
    description: Detects when sensitive audit policy sub-categories are disabled via event ID 4719.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.002
    data_sources:
      - security
      - windows
  - title: Auditpol.exe Used to Modify Audit Policy
    description: Detects usage of auditpol.exe to modify audit policy, a common technique to disable logging.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers often disable Windows auditing for security-sensitive audit policy sub-categories in an attempt to evade detection and forensic analysis on a system. This technique is part of a broader effort to impair defenses and hinder incident response. This detection identifies instances where specific audit policies, such as those related to logon events, process creation, and user account management, are disabled without being re-enabled within a defined time frame. This behavior is flagged by monitoring Windows Event ID 4719, which logs changes to audit policies. This rule is designed to detect potential attempts to undermine security monitoring and forensic capabilities on Windows endpoints.

## Attack Chain

1.  The attacker gains initial access to the system via phishing or exploiting a vulnerability (not described in source).
2.  The attacker escalates privileges to an administrator level, which is required to modify audit policies (not described in source).
3.  The attacker uses `auditpol.exe` or modifies Group Policy Objects (GPO) to disable specific audit policy sub-categories.
4.  The system generates Windows Event ID 4719, indicating a change in audit policy. This event contains information about the sub-category affected and the type of change (e.g., "Success removed").
5.  The attacker attempts to perform actions without being logged by disabling audit policies for events such as logon, process creation, or user account management.
6.  The attacker avoids detection by clearing or tampering with event logs to remove any traces of their activities (not described in source).
7.  The attacker continues with their malicious activities, such as lateral movement, data exfiltration, or deploying ransomware, with reduced risk of detection (not described in source).

## Impact

Successful disabling of audit policies can severely impair an organization's ability to detect and respond to security incidents. By removing critical audit logs, attackers can operate undetected, prolonging the duration of attacks and increasing the potential for data breaches, financial loss, and reputational damage. The absence of audit logs hinders forensic investigations, making it difficult to determine the scope and impact of an attack.

## Recommendation

*   Ensure the 'Audit Audit Policy Change' logging policy is configured for (Success, Failure) as outlined in the setup instructions, to generate the necessary event logs for detection.
*   Deploy the Sigma rule "Detect Audit Policy Sub-Category Disabled" to your SIEM to identify instances where sensitive audit policies are disabled.
*   Investigate any instances of Event ID 4719 where sensitive audit sub-categories are disabled, focusing on the associated processes and user accounts as described in the investigation steps.
*   Review and harden Group Policy settings related to audit policies to prevent unauthorized modifications, referencing Microsoft documentation on GPO management.
*   Enable Sysmon process creation logging to provide additional context around processes that modify audit policies.
