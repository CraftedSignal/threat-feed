---
title: Detection of Rapid Creation and Deletion of Windows Scheduled Tasks
slug: 2026-09-temporary-task-creation
description: Adversaries abuse the Windows Task Scheduler to execute malicious code and maintain persistence by creating and rapidly deleting tasks to obfuscate their footprint.
date: "2026-09-25T19:24:06Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - execution
  - windows
  - task-scheduler
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: Adversaries can use these to proxy malicious execution via the schedule service and perform clean up.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: Adversaries can use these to proxy malicious execution via the schedule service and perform clean up.
    confidence_band: high
references:
  - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_temp_scheduled_task.toml
rules:
  - title: Detect Temporarily Created Scheduled Tasks
    description: Detects the creation and subsequent deletion of a scheduled task within a 5-minute window, a technique used by adversaries to mask malicious execution.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable Audit Other Object Access Events on all domain-joined Windows endpoints.
      owner: IT Operations
      due: 72h
      evidence: Source setup guidance.
    - action: Deploy the EQL-based temporary task detection logic to monitor for rapid churn.
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided in threat brief.
  hunt_leads:
    - lead: Identify accounts frequently creating/deleting tasks within short windows.
      technique_id: T1053.005
      data_needed:
        - Security Event Log IDs 4698/4699
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source description of attack pattern.
---

Adversaries frequently target the Windows Task Scheduler to gain persistence and execute payloads under the context of elevated system accounts. To evade detection, sophisticated attackers employ a technique of creating a task to trigger a malicious script or binary and subsequently deleting the task within a very short timeframe. This behavior aims to reduce the window of opportunity for security tools and analysts to inspect the scheduled task configuration, its associated command lines, or its triggers. By observing the sequence of task creation followed immediately by task deletion on the same host, security teams can identify potentially unauthorized administrative activity or malicious proxy execution. This behavior is often characteristic of post-exploitation cleanup or the execution of temporary drop-exec payloads.

## Impact

Successful exploitation of this technique allows an attacker to achieve code execution or maintain persistence on a target system. Because the task is ephemeral, standard forensic analysis of the registry or task XML files may fail if the task is deleted before the next logging interval or alert triage. This technique increases the likelihood of an attacker establishing a foothold without leaving behind persistent, easily discoverable indicators.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
- Enable Windows \"Audit Other Object Access Events\" to ensure Event IDs 4698 (Task Created) and 4699 (Task Deleted) are logged.
- Deploy the provided Sigma rule to your SIEM to monitor for rapid task creation and deletion within a 5-minute window.
- Review and baseline existing administrative tasks or automated maintenance scripts that perform these actions to reduce false positive noise in the SIEM.
- Investigate alerts triggered by this rule by correlating the User Name and Task Name against known-good inventory and administrative account activity.
