---
title: Windows Event Logging Service Shutdown Detection
slug: 2024-01-03-windows-event-logging-shutdown
description: Detection of the Windows Event Log service shutdown, indicated by Event ID 1100, which can signify attempts to evade detection by disabling logging.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - windows
  - event-logging
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Windows Event Log
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1100
  - https://www.ired.team/offensive-security/defense-evasion/disabling-windows-event-logs-by-suspending-eventlog-service-threads
  - https://attack.mitre.org/techniques/T1070/001/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.001/T1070.001.md
rules:
  - title: Windows Event Logging Service Shutdown
    description: Detects the shutdown of the Windows Event Log service using Event ID 1100.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - event_log
      - windows
  - title: Suspicious Process Stopping Eventlog Service
    description: Detects a process attempting to stop the Windows Eventlog service via command line.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Windows Event Log service is a critical component for security monitoring and incident investigation. Attackers often disable or manipulate these logs to cover their tracks and hinder forensic analysis. Detecting the shutdown of the Windows Event Log service is crucial as it can indicate malicious activity, such as attempts to disable logging or cover tracks after an intrusion. Event ID 1100 in the Windows Security event log signifies that the event logging service has stopped. While legitimate system shutdowns can trigger this event, unexpected or unscheduled shutdowns should be investigated. This detection focuses on identifying instances where the service is stopped, potentially indicating malicious intent.

## Attack Chain

1.  Initial Access: An attacker gains initial access through various means, such as phishing or exploiting a vulnerability.
2.  Privilege Escalation: The attacker escalates privileges to gain administrative access to the system.
3.  Defense Evasion: The attacker attempts to disable or manipulate Windows Event Logs to evade detection.
4.  Service Stop: The attacker uses tools or commands to stop the Windows Event Log service (EventLog).
5.  Event ID 1100 Generated: Windows generates Event ID 1100 in the Security log, indicating the service has stopped.
6.  Malicious Activity: With logging disabled, the attacker performs malicious activities, such as installing malware, exfiltrating data, or lateral movement.
7.  Persistence: The attacker establishes persistence mechanisms to maintain access to the system.

## Impact

Successful disabling of the Windows Event Log service allows attackers to operate undetected, making incident response and forensic analysis significantly more challenging. This can lead to prolonged dwell time, increased data exfiltration, and greater overall damage to the organization. The absence of event logs hinders the ability to trace attacker activities, understand the scope of the breach, and implement effective remediation measures.

## Recommendation

*   Enable Windows Event Log collection and ensure that Security event logs are being forwarded to a central logging server for analysis (Windows Event Log Security 1100).
*   Deploy the Sigma rule provided in this brief to detect instances of Event ID 1100 in the Windows Security event log and tune for your environment.
*   Investigate any instances of Event ID 1100 promptly to determine if the shutdown of the Event Log service was authorized or malicious.
*   Implement additional monitoring and alerting for suspicious service control operations on critical systems.
