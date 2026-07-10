---
title: Windows Event Log Cleared
slug: 2024-01-09-windows-event-log-cleared
description: Detection of Windows event log clearing using Event IDs 1102 (Security) or 104 (System) which may indicate an attempt to hide malicious activity and impede forensic investigation.
date: "2024-01-09T18:22:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - windows
  - event-logs
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102
  - https://www.ired.team/offensive-security/defense-evasion/disabling-windows-event-logs-by-suspending-eventlog-service-threads
  - https://attack.mitre.org/techniques/T1070/001/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.001/T1070.001.md
rules:
  - title: Detect Windows Event Log Cleared (Security Log)
    description: Detects the clearing of the Windows Security event log (Event ID 1102), indicating potential evasion of detection.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - event_log
      - windows
  - title: Detect Windows Event Log Cleared (System Log)
    description: Detects the clearing of the Windows System event log (Event ID 104), indicating potential evasion of detection.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - event_log
      - windows
rules_count: 2
---

Attackers may clear Windows Event Logs to remove evidence of their activities and evade detection. This involves clearing the Security or System logs to hinder forensic investigations and maintain persistence within the compromised environment. This activity is often performed after successful exploitation, privilege escalation, or lateral movement within a network. This technique is particularly relevant in the context of ransomware attacks and other intrusions where attackers seek to cover their tracks. The clearing of logs can be done manually using tools like `wevtutil.exe` or through custom scripts. Monitoring for Event IDs 1102 and 104 provides crucial visibility into potential attempts to manipulate audit trails.

## Attack Chain

1. Initial access is gained through methods such as phishing or exploiting vulnerabilities.
2. The attacker performs reconnaissance to understand the network environment and identify valuable targets.
3. The attacker escalates privileges to gain administrative access, using exploits or credential theft.
4. The attacker disables or modifies security controls to weaken defenses.
5. Using `wevtutil.exe` or a custom script, the attacker clears the Windows Event Logs (Security or System) by triggering Event ID 1102 or 104.
6. The attacker performs lateral movement to access other systems within the network, using techniques such as pass-the-hash or pass-the-ticket.
7. The attacker performs data exfiltration, copying sensitive data to an external location.
8. Finally, the attacker deploys ransomware, encrypting files and demanding a ransom payment.

## Impact

Successful clearing of Windows Event Logs can severely impede incident response and forensic investigations. This can lead to delayed detection of breaches, prolonged attacker dwell time, and increased damage. In ransomware attacks, this can result in significant financial losses, reputational damage, and operational disruption. Depending on the organization, the disruption could impact critical infrastructure.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM to detect suspicious log clearing activities.
*   Enable and monitor Windows Event Log Security (Event ID 1102) and System (Event ID 104) logs.
*   Investigate any instances of Event ID 1102 or 104, and correlate with other alerts and data sources.
*   Implement strict access control policies to limit who can clear event logs.
*   Utilize host-based intrusion detection systems (HIDS) to monitor for suspicious processes and file modifications related to log clearing.
*   Regularly review and audit event log settings to ensure proper configuration and retention policies.
