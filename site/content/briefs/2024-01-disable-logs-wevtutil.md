---
title: Detection of Wevtutil.exe Used to Disable Event Logs
slug: 2024-01-disable-logs-wevtutil
description: The execution of `wevtutil.exe` with parameters to disable event logs is a tactic commonly employed by ransomware to evade detection and hinder forensic investigations, leading to a significant reduction in visibility for defenders.
date: "2024-01-04T16:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - ransomware
  - windows
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://www.bleepingcomputer.com/news/security/new-ransom-x-ransomware-used-in-texas-txdot-cyberattack/
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/disable_logs_using_wevtutil.yml
rules:
  - title: Detect Wevtutil.exe Disabling Event Logs via Commandline
    description: Detects the execution of wevtutil.exe with command-line arguments used to disable event logs.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Wevtutil.exe Clearing Event Logs via Commandline
    description: Detects the execution of wevtutil.exe with command-line arguments used to clear event logs.
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

Attackers, particularly ransomware groups, often disable or manipulate event logs to cover their tracks and hinder forensic investigations. This activity typically occurs post-compromise as part of an attacker's defense evasion strategy. The use of `wevtutil.exe`, a legitimate Windows command-line utility, makes this technique challenging to detect without specific monitoring. Ransomware actors disable logging to operate undetected, making it difficult for security teams to trace malicious activities and respond effectively. This can prolong the dwell time of the attacker within the environment and increase the potential for widespread damage, data exfiltration, or system encryption.

## Attack Chain

1. Initial access is gained through typical methods like phishing or exploiting public-facing vulnerabilities.
2. The attacker executes code on the compromised system, achieving initial foothold.
3. Privilege escalation techniques are employed to gain elevated permissions (e.g., using exploits, token manipulation).
4. The attacker uses `wevtutil.exe` with specific commands to disable or clear event logs. Example commands include `wevtutil.exe sl <logname> false` or `wevtutil.exe set-log <logname> /enabled:false`.
5. The attacker disables specific event channels to remove evidence of their activity.
6. Persistence mechanisms are established to maintain access across reboots (e.g., creating scheduled tasks, modifying registry keys).
7. Lateral movement is initiated to compromise additional systems within the network using tools like PsExec or SMB shares.
8. The final objective, such as ransomware deployment or data exfiltration, is executed, with logging disabled to minimize the chances of detection.

## Impact

Successful disabling of event logs allows attackers to operate undetected, hindering forensic investigations and incident response efforts. This can lead to delayed detection of breaches, prolonged dwell time for attackers, and increased damage to affected organizations. Ransomware groups frequently use this technique to maximize the impact of their attacks, resulting in data encryption, exfiltration, and significant financial losses.

## Recommendation

*   Enable Sysmon process creation logging (Event ID 1) to detect the execution of `wevtutil.exe` with suspicious parameters.
*   Deploy the Sigma rules provided below to your SIEM to detect specific command-line arguments used to disable event logs.
*   Monitor Windows Event Log Security (4688) for process creation events of `wevtutil.exe` with arguments related to disabling or clearing logs.
*   Investigate any instances where `wevtutil.exe` is executed with parameters like `sl` or `set-log` and `/e:false` or `/enabled:false` in the command line, as highlighted in the provided Sigma rules.
