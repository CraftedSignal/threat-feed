---
title: Detection of Event Log Disabling via WevtUtil
slug: 2024-01-disable-logs-wevtutil
description: Detection of the 'wevtutil.exe' command-line utility being used to disable event logs, a common tactic employed by ransomware actors to evade detection and hinder forensic analysis on compromised Windows systems.
date: "2024-01-03T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - ransomware
  - windows
  - wevtutil
vendors:
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
  - https://www.bleepingcomputer.com/news/security/new-ransom-x-ransomware-used-in-texas-txdot-cyberattack/
rules:
  - title: Detect WevtUtil Disable Log Command
    description: Detects the execution of wevtutil.exe with command line arguments to disable an event log
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.002
    data_sources:
      - process_creation
      - windows
  - title: Detect WevtUtil Clear Log Command
    description: Detects the execution of wevtutil.exe with command line arguments to clear an event log
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

This brief focuses on the detection of adversaries disabling Windows event logs using the `wevtutil.exe` utility. Disabling or clearing event logs is a common defense evasion technique employed by ransomware actors and other malicious actors to remove evidence of their activities and impede incident response. The detection logic centers around identifying specific command-line parameters used with `wevtutil.exe` that indicate an attempt to disable or clear logs. This activity, if successful, allows attackers to operate with reduced visibility, complicating investigations and potentially extending the duration of the compromise. The activity is detected via process monitoring data from EDR solutions and Windows Event Logs.

## Attack Chain

1.  Initial Access: The attacker gains initial access to the target system through various means, such as phishing, exploitation of a vulnerability, or compromised credentials.
2.  Privilege Escalation: The attacker escalates privileges to gain necessary permissions to disable event logs, typically requiring local administrator rights.
3.  Defense Evasion: The attacker executes `wevtutil.exe` with specific command-line arguments to disable or clear event logs, such as `wevtutil.exe sl <logname> /e:false` or `wevtutil.exe set-log <logname> /enabled:false`.
4.  Log Manipulation: The attacker targets specific event logs, such as the Security, Application, or System logs, to remove traces of their activity.
5.  Persistence: In some cases, the attacker might establish persistence through scheduled tasks or registry modifications to ensure continued access even after system reboots.
6.  Lateral Movement: The attacker might use the compromised system as a pivot point to move laterally to other systems on the network, repeating the log disabling process to cover their tracks.
7.  Data Encryption/Exfiltration: After disabling logs and moving laterally, the attacker deploys ransomware to encrypt data, or exfiltrates sensitive information from the compromised environment.
8.  Impact: The attacker achieves their final objective, whether it's data encryption for ransom or exfiltration of sensitive information, with reduced chances of detection and successful investigation due to disabled logs.

## Impact

Disabling or clearing event logs allows attackers to operate undetected for extended periods, increasing the dwell time and potential for damage. This activity can lead to significant data loss, financial losses due to ransomware demands, reputational damage, and increased costs associated with incident response and recovery. In cases like the Ransom X ransomware attack (referenced in the original source), disabling logs was a key step in hiding malicious activity. The lack of log data makes incident response significantly more difficult and time-consuming.

## Recommendation

*   Deploy the Sigma rules provided in this brief to your SIEM or EDR solution to detect instances of `wevtutil.exe` being used to disable event logs.
*   Enable and monitor process creation logs (Sysmon Event ID 1 or Windows Event Log Security 4688) with command-line arguments to capture the execution of `wevtutil.exe` with potentially malicious parameters.
*   Investigate any alerts triggered by these rules promptly to determine if the activity is legitimate or indicative of malicious behavior.
*   Implement strict access controls and principle of least privilege to limit the number of users who can execute `wevtutil.exe` or modify event log settings.
*   Review and harden your endpoint detection and response (EDR) configurations to ensure comprehensive process monitoring and event logging capabilities.
*   Consider using an immutable logging solution to prevent attackers from tampering with log data, ensuring that audit trails remain intact.
