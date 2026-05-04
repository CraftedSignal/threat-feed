---
title: Windows Scheduled Task Creation for Persistence
slug: 2024-01-02-scheduled-task-creation
description: Adversaries may create scheduled tasks on Windows systems to establish persistence, move laterally, or escalate privileges, and this detection identifies such activity by monitoring Windows event logs for scheduled task creation events, excluding known benign tasks and those created by system accounts.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - scheduled-task
  - windows
vendors:
  - Microsoft
  - Hewlett-Packard
  - Mozilla
  - Google
products:
  - OneDrive
  - Visual Studio
  - Office
  - Firefox
  - Windows
  - HP Support Assistant
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
references:
  - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698
  - https://attack.mitre.org/techniques/T1053/
  - https://attack.mitre.org/techniques/T1053/005/
rules:
  - title: Detect Scheduled Task Creation via Schtasks.exe
    description: Detects scheduled task creation using schtasks.exe command-line utility, excluding common benign tasks.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Scheduled Task Creation via PowerShell
    description: Detects scheduled task creation via PowerShell, filtering out legitimate tasks.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
  - title: Detect Scheduled Task Creation with Uncommon Executables
    description: Detects scheduled task creation events where the task executes uncommon or suspicious executables.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Adversaries frequently leverage scheduled tasks in Windows to maintain persistence, elevate privileges, or facilitate lateral movement within a compromised network. This technique involves creating or modifying scheduled tasks to execute malicious code at specific times or intervals. The detection rule focuses on identifying the creation of new scheduled tasks logged in Windows event logs, filtering out tasks created by system accounts and those associated with legitimate software to minimize false positives. This detection is crucial because successful exploitation allows attackers to execute arbitrary commands or programs on a recurring basis, maintaining a foothold even after system reboots or user logoffs. Defenders need to monitor for anomalous task creation events to identify potential malicious activity. The rule references Microsoft Event ID 4698 as a key data source for detecting scheduled task creation.

## Attack Chain

1. **Initial Access:** An attacker gains initial access to the system through phishing, exploiting a vulnerability, or using compromised credentials.
2. **Privilege Escalation (if needed):** The attacker escalates privileges using exploits or by abusing misconfigurations to gain the necessary permissions to create scheduled tasks.
3. **Task Creation:** The attacker creates a new scheduled task using tools like `schtasks.exe` or PowerShell.
4. **Configuration:** The attacker configures the task to execute a malicious script or program at a specific time or event trigger.
5. **Persistence:** The scheduled task is configured to run at regular intervals or upon system startup, ensuring persistent access to the compromised system.
6. **Execution:** When the scheduled task triggers, the malicious payload executes, performing actions such as installing malware, stealing data, or establishing a command and control connection.
7. **Lateral Movement (optional):** The attacker uses the compromised system and scheduled task to move laterally to other systems on the network, repeating the task creation process.

## Impact

Successful exploitation via scheduled task creation can lead to persistent access within the compromised environment. The attacker can maintain a foothold even after system restarts, enabling them to perform data exfiltration, deploy ransomware, or cause other disruptive activities. While the risk score is relatively low, the potential for persistence makes this a critical area to monitor, especially in environments where lateral movement is a significant concern. The number of affected systems depends on the scope of the initial compromise and the attacker's ability to move laterally.

## Recommendation

*   Enable "Audit Other Object Access Events" to generate the necessary Windows Security Event Logs for detecting scheduled task creation (reference: setup instructions in the original rule).
*   Deploy the provided Sigma rules to your SIEM to detect suspicious scheduled task creation events, and tune the rules by adding exclusions for known benign tasks in your environment.
*   Review the investigation steps outlined in the rule's notes to triage alerts related to scheduled task creation, focusing on unfamiliar task names, unusual user accounts, and suspicious scheduled actions.
*   Use the `references` URL to understand the specific details of Windows Event ID 4698, which is generated when a scheduled task is created.
