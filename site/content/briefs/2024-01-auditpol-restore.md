---
title: Windows Audit Policy Restored via Auditpol.exe
slug: 2024-01-auditpol-restore
description: Attackers may use auditpol.exe with the /restore argument to replace the existing audit policy with a malicious one, disabling auditing to evade detection, potentially leading to full machine compromise or lateral movement.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - auditpol
  - audit-policy
  - defense-evasion
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.microsoft.com/en-us/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/
  - https://www.cybereason.com/blog/research/prometei-botnet-exploiting-microsoft-exchange-vulnerabilities
  - https://attack.mitre.org/techniques/T1562/002/
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-restore
rules:
  - title: Auditpol.exe Restoring Audit Policy
    description: Detects the execution of auditpol.exe with the /restore parameter, which can be used to disable or modify audit logging.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.002
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Parent Process of Auditpol.exe Restore
    description: Detects auditpol.exe restoring audit policy from unusual parent processes.
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

Attackers or red teams may use `auditpol.exe` with the `/restore` command-line argument to restore the audit policy from a file, potentially disabling crucial security logging. This technique is significant because it allows adversaries to bypass defenses and plan further attacks without being detected. The activity is typically observed using Endpoint Detection and Response (EDR) agents that monitor process executions and command-line arguments. The goal is often to limit the data available for detections and audits, creating a blind spot for defenders. Disabling or modifying audit policies can precede or accompany other malicious activities to hinder incident response and forensic investigations.

## Attack Chain

1. The attacker gains initial access to the system (e.g., through compromised credentials or exploiting a vulnerability).
2. The attacker elevates privileges to a level where they can modify the audit policy.
3. The attacker prepares a malicious audit policy file that disables or reduces auditing.
4. The attacker executes `auditpol.exe` with the `/restore` parameter, specifying the path to the malicious audit policy file.
5. `auditpol.exe` replaces the existing audit policy with the attacker-supplied policy.
6. Auditing is reduced or disabled, preventing the collection of security-relevant events.
7. The attacker performs malicious activities, such as lateral movement, data exfiltration, or installing malware, without being properly logged.
8. The attacker achieves their objective with a reduced risk of detection.

## Impact

Successful execution of this technique can severely impair an organization's ability to detect and respond to attacks. By disabling or reducing audit logging, attackers can operate with impunity, making it difficult to trace their actions and identify compromised systems. This can lead to a delayed response, allowing attackers to cause more damage, exfiltrate sensitive data, or establish a persistent foothold in the network. The impact ranges from data breaches and financial losses to reputational damage and legal liabilities.

## Recommendation

*   Deploy the Sigma rule `Auditpol.exe Restoring Audit Policy` to your SIEM and tune for your environment to detect suspicious `auditpol.exe` executions.
*   Monitor process creation events (Sysmon EventID 1, Windows Event Log Security 4688) for `auditpol.exe` executions with the `/restore` argument.
*   Implement strict access controls to prevent unauthorized modification of audit policies.
*   Review audit policy configurations regularly to ensure they have not been tampered with.
*   Whitelist legitimate uses of `auditpol.exe /restore` with known parent processes to reduce false positives, as described in the Known False Positives section.
*   Investigate any instances of `auditpol.exe /restore` as high-priority incidents, given the potential for defense evasion.
