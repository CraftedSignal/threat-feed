---
title: Windows Audit Policy Cleared via Auditpol
slug: 2024-01-auditpol-clear
description: The execution of `auditpol.exe` with the `/clear` or `/remove` command-line arguments indicates potential defense evasion by adversaries or Red Teams, aiming to limit data that can be leveraged for detections and audits, potentially leading to full machine compromise or lateral movement.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - defense-evasion
  - audit-tampering
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
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-clear
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-remove
rules:
  - title: Detect Auditpol Clear Command
    description: Detects the execution of auditpol.exe with the /clear command-line argument, indicating a potential attempt to clear audit policies.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Auditpol Remove Command
    description: Detects the execution of auditpol.exe with the /remove command-line argument, indicating a potential attempt to remove audit policies.
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

Attackers, including Red Teams, may attempt to disable or clear Windows audit policies to evade detection and prevent security analysts from identifying malicious activity. This involves using the `auditpol.exe` utility with the `/clear` or `/remove` command-line arguments, effectively erasing existing audit configurations. This action eliminates crucial data points that security teams rely on for detecting and responding to threats. By clearing audit policies, adversaries can operate with a reduced risk of being detected, potentially allowing for prolonged access and further exploitation of compromised systems. The activity is significant as it indicates a deliberate attempt to subvert security measures and gain an advantage within the targeted environment.

## Attack Chain

1. The attacker gains initial access to the target system (e.g., via compromised credentials or exploiting a vulnerability).
2. The attacker escalates privileges to an account with sufficient permissions to modify audit policies.
3. The attacker executes `auditpol.exe` with the `/clear` or `/remove` command-line argument.
4. The `auditpol.exe` process modifies the system's audit policy settings.
5. Windows event logging is disabled or significantly reduced due to the cleared audit policy.
6. The attacker performs malicious activities without generating standard audit logs.
7. The attacker moves laterally within the network to compromise additional systems.
8. The attacker achieves their final objective, such as data theft or deploying ransomware.

## Impact

Clearing the Windows audit policy can have a severe impact on an organization's security posture. The lack of audit logs hinders incident response efforts, making it difficult to investigate security incidents and identify compromised systems. Attackers can move laterally, steal sensitive data, or deploy ransomware without triggering standard alerts. This can result in significant financial losses, reputational damage, and regulatory penalties. In some instances, attackers might clear audit policies as a precursor to a larger attack campaign, such as the Solorigate supply chain attack.

## Recommendation

*   Deploy the Sigma rule `Detect Auditpol Clear Command` to your SIEM to identify instances of `auditpol.exe` being used to clear audit policies.
*   Enable Sysmon process creation logging (Event ID 1) to capture the execution of `auditpol.exe` with command-line arguments.
*   Monitor Windows Event Log Security events (4688) for process creation events related to `auditpol.exe`.
*   Investigate any instances where `auditpol.exe` is executed with the `/clear` or `/remove` arguments, as this could indicate malicious activity.
*   Implement strict access controls to limit the number of accounts that can modify audit policies.
*   Deploy the Sigma rule `Detect Auditpol Remove Command` to detect `auditpol.exe` executions with `/remove`.
