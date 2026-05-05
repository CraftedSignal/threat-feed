---
title: Suspicious Wevtutil Usage for Clearing Windows Event Logs
slug: 2024-01-suspicious-wevtutil
description: Detection of wevtutil.exe being used with parameters to clear event logs, indicating potential attempts to evade detection and hinder forensic investigations by adversaries.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - windows
  - log-manipulation
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.001/T1070.001.md
rules:
  - title: Suspicious Wevtutil Usage
    description: Detects the usage of wevtutil.exe with parameters for clearing event logs.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Wevtutil Usage - Alternate
    description: Detects the usage of wevtutil.exe with parameters for clearing event logs using alternate syntax.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The following analytic detects the suspicious usage of `wevtutil.exe` to clear Windows event logs, including critical logs like Application, Security, Setup, Trace, and System. This behavior is often associated with threat actors attempting to remove evidence of their activities, thereby hindering incident response and forensic analysis. The detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant because clearing event logs can be an attempt to cover tracks after malicious actions, hindering forensic investigations. If confirmed malicious, this behavior could allow an attacker to erase evidence of their activities, making it difficult to trace their actions and understand the full scope of the compromise.

## Attack Chain

1.  Initial Access: An attacker gains initial access to a system through various means (e.g., phishing, exploiting vulnerabilities).
2.  Privilege Escalation: The attacker elevates privileges to gain the necessary permissions to manipulate event logs.
3.  Credential Access: The attacker attempts to obtain valid credentials.
4.  Defense Evasion: The attacker uses `wevtutil.exe` with specific parameters to clear security, application, system, or other event logs. The command line includes arguments such as "cl" or "clear-log" followed by the name of the log to clear (e.g., `wevtutil cl Security`).
5.  Persistence: The attacker may establish persistence mechanisms to maintain access to the compromised system.
6.  Lateral Movement: The attacker moves laterally to other systems within the network, repeating the steps of privilege escalation and log clearing.
7.  Exfiltration/Impact: Depending on the attacker's objectives, they may exfiltrate sensitive data or cause damage to the system or network.

## Impact

Successful clearing of event logs can severely impair an organization's ability to detect and respond to security incidents. This can lead to delayed detection of breaches, increased dwell time for attackers, and difficulty in understanding the full extent of a compromise. The loss of log data can also hinder compliance efforts and legal investigations.

## Recommendation

*   Deploy the Sigma rule `Suspicious Wevtutil Usage` to your SIEM and tune for your environment to detect the clearing of event logs using `wevtutil.exe`.
*   Enable Sysmon process-creation logging (Event ID 1) and Windows Event Log Security logging (Event ID 4688) to ensure the necessary data is available for the detection rule.
*   Investigate any detected instances of `wevtutil.exe` being used to clear logs, focusing on the parent process, user account, and affected system.
*   Monitor endpoint logs for unusual or unauthorized use of command-line tools for log manipulation.
