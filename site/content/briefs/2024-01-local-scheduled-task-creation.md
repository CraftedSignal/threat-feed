---
title: Suspicious Local Scheduled Task Creation
slug: 2024-01-local-scheduled-task-creation
description: This rule detects the creation of scheduled tasks on Windows systems by non-system accounts, a common technique used by adversaries for persistence, lateral movement, and privilege escalation.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - windows
  - scheduled_task
  - attack.persistence
vendors:
  - Elastic
products:
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
references:
  - https://www.elastic.co/security-labs/hunting-for-persistence-using-elastic-security-part-1
  - https://www.elastic.co/security-labs/hunting-for-persistence-using-elastic-security-part-2
  - https://www.elastic.co/security-labs/invisible-miners-unveiling-ghostengine
  - https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper
  - https://attack.mitre.org/techniques/T1053/
  - https://attack.mitre.org/techniques/T1053/005/
rules:
  - title: Scheduled Task Creation by Non-System Account
    description: Detects the creation of scheduled tasks using schtasks.exe by non-SYSTEM accounts.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Process Creating Scheduled Task
    description: Detects suspicious processes spawning schtasks.exe to create scheduled tasks
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Adversaries frequently abuse scheduled tasks in Windows to maintain persistence, move laterally within a network, or escalate privileges. This involves creating or modifying scheduled tasks to execute malicious commands or scripts at specific times or intervals. This detection rule focuses on identifying the creation of scheduled tasks by non-system accounts, which is often indicative of malicious activity. The rule specifically monitors for the execution of `schtasks.exe` with specific arguments related to task creation. It is designed to trigger when scheduled tasks are created by non-system level users, helping to filter out legitimate administrative activities. This is crucial for defenders because scheduled tasks provide a reliable and stealthy mechanism for attackers to maintain control over compromised systems.

## Attack Chain

1. An attacker gains initial access to a Windows system through various means.
2. The attacker executes a command shell (e.g., cmd.exe, PowerShell) or script interpreter (e.g., wscript.exe) on the compromised system.
3. The attacker uses `schtasks.exe` with the `/create` parameter to create a new scheduled task.
4. The `/TN` parameter is used to specify the name of the task, and the `/TR` parameter defines the program or script to execute.
5. The `/SC` parameter sets the schedule for the task (e.g., daily, hourly, onlogon), and `/RU` specifies the user account under which the task will run.
6. The attacker configures the task to run with elevated privileges or under a non-system account to bypass security controls.
7. The scheduled task executes the attacker's payload at the specified time or event, achieving persistence.
8. The payload may perform various malicious actions, such as installing malware, exfiltrating data, or establishing a command and control channel.

## Impact

Successful exploitation can lead to persistent access to the compromised system, allowing attackers to maintain control even after reboots or user logoffs. Attackers can leverage scheduled tasks to escalate privileges, potentially gaining access to sensitive data or critical system resources. The creation of unauthorized scheduled tasks can also be used to move laterally within the network, compromising additional systems and expanding the scope of the attack.

## Recommendation

- Enable Sysmon process creation logging with Event ID 1 to capture command-line arguments and process details (reference: Sysmon setup in rule setup).
- Deploy the Sigma rule "Scheduled Task Creation by Non-System Account" to your SIEM to detect suspicious schtasks.exe activity.
- Review and whitelist legitimate scheduled task creation activities in your environment to reduce false positives (reference: False positive analysis).
- Monitor process activity for processes such as cmd.exe, powershell.exe, wscript.exe creating scheduled tasks (reference: query).
- Investigate any scheduled tasks created by non-system accounts that do not have a clear business justification (reference: Investigation Guide).
