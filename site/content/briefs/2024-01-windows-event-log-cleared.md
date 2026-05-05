---
title: Windows Event Log Cleared
slug: 2024-01-windows-event-log-cleared
description: Detection of cleared Windows event logs (Security Event ID 1102 or System log event 104) indicates potential defense evasion and obfuscation by threat actors attempting to remove evidence of their activities.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - impact
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
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
  - title: Windows Event Log Cleared - Security Log
    description: Detects clearing of the Windows Security event log (Event ID 1102), indicating potential evasion.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - event_log
      - windows
  - title: Windows Event Log Cleared - System Log
    description: Detects clearing of the Windows System event log (Event ID 104), indicating potential evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - event_log
      - windows
rules_count: 2
---

Windows Event Log clearing is a technique used by attackers to remove traces of their activity from a compromised system. This behavior, often associated with post-exploitation phases, involves deleting or overwriting event logs to hinder forensic investigations. The technique is often seen after initial access, privilege escalation, or lateral movement. Attackers leverage native Windows utilities or custom tools to clear these logs. Detecting and responding to event log clearing is crucial for maintaining visibility into security incidents and preventing prolonged attacker persistence. This detection focuses on Event ID 1102 (Security log cleared) and Event ID 104 (System log cleared).

## Attack Chain

1.  Initial access is gained through various methods, such as exploiting vulnerabilities or using stolen credentials.
2.  The attacker escalates privileges to gain administrative rights on the system.
3.  The attacker identifies critical event logs containing evidence of their activities.
4.  The attacker executes commands to clear the targeted event logs (Security or System logs).
5.  Windows Event Log service processes the request and clears the specified logs, generating Event ID 1102 (Security) or 104 (System).
6.  The attacker attempts to disable or suspend the event logging service.
7.  The attacker performs further malicious activities, relying on the reduced visibility.
8.  The attacker achieves their final objective, such as data exfiltration or ransomware deployment.

## Impact

Successful clearing of Windows event logs severely impairs incident response and forensic analysis capabilities. Without proper logging, security teams may be unable to determine the scope and nature of an attack, leading to delayed or ineffective remediation. This can allow attackers to maintain persistence within the environment, increasing the potential for data breaches, financial loss, and reputational damage.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM to detect suspicious event log clearing activities based on EventCode 1102 and 104.
*   Enable and monitor Windows Event Log Security (Event ID 1102) and System logs (Event ID 104) on critical systems.
*   Implement strong access controls and auditing policies to restrict who can clear event logs.
*   Investigate any instances of event log clearing, as it is often indicative of malicious activity.
*   Correlate event log clearing events with other security alerts and data sources to gain a comprehensive understanding of potential incidents.
