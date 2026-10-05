---
title: Detection of Malicious Windows Scheduled Task Names
slug: 2026-10-suspicious-scheduled-tasks
description: Detection logic targeting the creation, modification, or enabling of Windows Scheduled Tasks that utilize known malicious or suspicious naming conventions often associated with persistence and payload execution.
date: "2026-10-05T12:27:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - scheduled-tasks
  - windows
  - detection-engineering
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
    evidence: The following analytic detects the creation, modification, or enabling of scheduled tasks with known suspicious or malicious task names.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: This activity is significant as it may indicate an attempt to establish persistence or execute malicious commands on a system.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1053/005/
  - https://www.ic3.gov/CSA/2023/231213.pdf
  - https://news.sophos.com/en-us/2024/11/06/bengal-cat-lovers-in-australia-get-psspsspssd-in-google-driven-gootloader-campaign/
  - https://github.com/mthcht/awesome-lists/blob/main/Lists/suspicious_windows_tasks_list.csv
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable Windows Security Event ID 4698, 4700, 4702 logging.
      owner: IT Operations
      due: 24h
      evidence: Source document identifies these IDs as required for detection.
  hunt_leads:
    - lead: Identify all existing scheduled tasks with uncommon or suspicious naming conventions.
      technique_id: T1053.005
      data_needed:
        - Windows Security Event Logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: General TTP monitoring approach.
  mitigation_plan:
    - priority: medium_term
      action: Review and restrict permissions for non-administrative users to create or modify scheduled tasks.
      owner: IT Operations
      addresses: T1053.005
      evidence: Standard hardening practice.
---

This brief addresses the use of Windows Scheduled Tasks by threat actors to establish persistence, elevate privileges, or facilitate the execution of malicious code. Attackers frequently register tasks with specific naming patterns to mask their activity or follow naming conventions identified in previous campaigns. Defenders can identify this activity by monitoring Windows Security Event logs for task creation (4698), modification (4702), and enablement (4700). Security teams should monitor for these events and compare registered task names against internal watchlists or intelligence-derived lists of known suspicious task names. This analytic is particularly relevant for identifying techniques employed by diverse threat groups, including those associated with ransomware families like Ryuk and various information stealers.

## Impact

Successful exploitation of scheduled tasks enables threat actors to maintain long-term unauthorized access to a system, execute arbitrary payloads with elevated permissions, or bypass basic security controls. This activity is a common precursor to wider network compromise, data exfiltration, or ransomware deployment. Organizations may face significant operational disruption and data loss if persistent malicious tasks remain undetected.

## Recommendation

- Enable Windows Security Event Log auditing for Task Scheduler events (Event IDs 4698, 4700, 4702) across all endpoints.
- Implement a centralized watchlist of suspicious task names derived from threat intelligence to flag anomalous registrations.
- Investigate any scheduled task creation that includes shell commands or binary execution paths from suspicious directories (e.g., Temp, AppData).
- Use the provided drilldown searches to correlate alerts with user identity and system context to distinguish between administrative tasks and malicious activity.
