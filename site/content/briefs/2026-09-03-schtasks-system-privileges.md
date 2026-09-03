---
title: Detection of Scheduled Tasks Created with SYSTEM Privileges
slug: 2026-09-03-schtasks-system-privileges
description: Adversaries often leverage Windows scheduled tasks to establish persistence or execute code with NT AUTHORITY\SYSTEM privileges, a technique commonly observed in various malware campaigns.
date: "2026-09-03T12:44:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - privilege-escalation
  - windows
  - schtasks
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: Detects the creation or update of a scheduled task to run with NT AUTHORITY\SYSTEM privileges
    confidence_band: high
references:
  - https://www.elastic.co/security-labs/exploring-the-qbot-attack-pattern
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks
rules:
  - title: Detect Schtasks Creation Or Modification With SYSTEM Privileges
    description: Detects the creation or update of a scheduled task to run with NT AUTHORITY\SYSTEM privileges
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
      - privilege-escalation
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule 89ca78fd-b37c-4310-b3d3-81a023f83936 to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided in source
  mitigation_plan:
    - priority: medium_term
      action: Review scheduled tasks via Group Policy or PowerShell to ensure only known tasks run as SYSTEM
      owner: IT Operations
      evidence: General security hardening guidance
---

The creation or modification of scheduled tasks running under the context of the NT AUTHORITY\SYSTEM account is a high-confidence indicator of potential privilege escalation or persistence. Attackers utilize the 'schtasks.exe' utility to register new tasks or modify existing ones to execute malicious payloads with elevated administrative privileges. This technique allows an attacker to maintain a foothold on the system that survives user logoffs and reboots, often running their code in the most privileged security context available on a Windows workstation or server. While legitimate software, such as update agents or system management tools, occasionally creates SYSTEM-level tasks, these activities typically follow predictable installation patterns. Defenders should monitor for command-line arguments involving '/create' or '/change' coupled with '/ru SYSTEM' or variants of 'NT AUTHORITY' to identify unauthorized execution attempts.

## Attack Chain

1. Attacker gains initial access to the Windows host through phishing, exploit, or credential theft.
2. Attacker stages a malicious binary or script (e.g., in 'C:\\ProgramData' or 'C:\\Users\\Public').
3. Attacker uses 'schtasks.exe' to define a new task execution profile.
4. The command includes the '/ru SYSTEM' flag to specify the execution context.
5. The attacker sets the task to trigger at a specific interval or event (e.g., system startup).
6. The task scheduler service registers the task under the specified security context.
7. The system triggers the task execution at the scheduled time.
8. The malicious payload executes with SYSTEM privileges, enabling full system control or credential dumping.

## Impact

Successful abuse of scheduled tasks to run as SYSTEM typically results in full compromise of the affected host. Attackers may deploy ransomware, exfiltrate sensitive data, or install additional rootkits. This technique is pervasive across all sectors, as it is a foundational step in many post-exploitation frameworks and commodity malware, including variants of Qbot.

## Recommendation

1. Deploy the provided Sigma rule to detect 'schtasks.exe' invocations that specify SYSTEM-level privilege escalation.
2. Baseline your environment by identifying legitimate software that creates SYSTEM-level tasks to tune out false positives.
3. Monitor process creation events (Event ID 4688 or Sysmon Event ID 1) specifically for 'schtasks.exe' with the '/ru' flag.
4. Use the whitelist filters provided in the rule logic to suppress alerts for known benign administrative tools and installers.
