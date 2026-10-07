---
title: Detection of Unauthorized Scheduled Task Modifications
slug: 2026-10-unusual-scheduled-task-update
description: This detection brief identifies potential persistence mechanisms where non-system users modify Windows scheduled tasks to execute malicious code.
date: "2026-10-07T16:42:07Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - windows
  - security-monitoring
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
    evidence: Adversaries can exploit them for persistence by modifying tasks to execute malicious code.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4702
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_scheduled_task_updated.toml
rules:
  - title: Detect Unusual Scheduled Task Update
    description: Detects the first-time modification of a scheduled task by a non-system user account, which may indicate persistence activity.
    platform: sigma
    severity: low
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
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable Audit Other Object Access events across the domain.
      owner: IT Operations
      due: 72h
      evidence: Source setup instructions.
  hunt_leads:
    - lead: Search for Event ID 4702 occurrences involving non-system accounts.
      technique_id: T1053.005
      data_needed:
        - Windows Security Event Logs
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Rule description documentation.
  mitigation_plan:
    - priority: short_term
      action: Review all existing scheduled tasks for unauthorized changes.
      owner: SOC
      addresses: T1053.005
      evidence: Triage and analysis section.
---

Adversaries frequently leverage the Windows Task Scheduler to maintain persistence by modifying existing tasks to execute malicious binaries or scripts. While scheduled tasks are essential for system automation, unauthorized modifications by non-system user accounts are often indicative of malicious activity. 

This brief focuses on the detection of event ID 4702, which records when a scheduled task is updated. By filtering out system and machine accounts (S-1-5-18, S-1-5-19, S-1-5-20), defenders can isolate modifications performed by standard or administrative user accounts. This approach helps in identifying anomalous task updates that may deviate from baseline administrative behavior. Defenders should prioritize investigating modifications that involve suspicious script paths or infrequent task names to distinguish between routine maintenance and potential persistence attempts.

## Impact

Successful abuse of scheduled tasks allows attackers to achieve long-term persistence on compromised endpoints, enabling them to execute malicious payloads automatically at system startup, user login, or specific time intervals. This technique facilitates further stages of an attack, such as credential harvesting, lateral movement, or data exfiltration.

## Recommendation

Prioritize the implementation of the following detection logic to monitor for unauthorized modifications.

* Enable "Audit Other Object Access" events in Windows Group Policy to ensure Event ID 4702 is captured.
* Deploy the provided Sigma rule to your SIEM environment to monitor for task updates by non-system accounts.
* Maintain a baseline of legitimate scheduled task modifications associated with software deployment tools and administrative maintenance to reduce false positive noise.
* Investigate triggered alerts by cross-referencing the modified task command or script path with known-good organizational baselines.
