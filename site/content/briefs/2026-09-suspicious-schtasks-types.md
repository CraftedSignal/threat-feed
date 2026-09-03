---
title: Suspicious Task Scheduling via Schtasks
slug: 2026-09-suspicious-schtasks-types
description: Detection of potentially malicious scheduled task creation or modification using specific trigger types that often bypass standard administrative activity monitoring.
date: "2026-09-03T12:44:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - windows
  - schtasks
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: The schtasks utility is a core component used for task persistence as documented in the provided Sigma rule.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create
  - http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
rules:
  - title: Detect Suspicious Schtasks Schedule Types
    description: Detects scheduled task creation or modification using specific trigger types (ONLOGON, ONSTART, ONCE, ONIDLE) that do not specify high-privilege execution, which is often indicative of malicious persistence attempts.
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
    - action: Deploy the Sigma rule to the SIEM and run in monitor-only mode for 7 days to baseline volume.
      owner: Detection Engineering
      due: 24h
  hunt_leads:
    - lead: Search for existing tasks created with /sc ONLOGON or /sc ONSTART that do not have an associated SYSTEM or HIGHEST execution context.
      technique_id: T1053.005
      data_needed:
        - Scheduled Task logs or Schtasks output
      priority: medium
      confidence: medium
      disposition: hunt_now
  mitigation_plan:
    - priority: medium_term
      action: Restrict the ability of non-administrative users to create or modify scheduled tasks via Group Policy.
      owner: IT Operations
---

This brief addresses the use of the `schtasks.exe` utility to create or modify tasks using specific, non-standard trigger types such as `ONLOGON`, `ONSTART`, `ONCE`, and `ONIDLE`. While these parameters are legitimate administrative functions within the Windows operating system, they are frequently abused by threat actors for persistence and lateral movement. Attackers leverage these schedule types to ensure malicious payloads execute automatically upon system startup, user logon, or during periods of inactivity. This activity has been observed in campaigns attributed to actors such as the Lazarus Group, who utilize scheduled tasks to maintain access and execute follow-on payloads. Defenders must distinguish between routine enterprise management activity and unauthorized task creation that lacks elevated (SYSTEM or HIGHEST) execution context.

## Impact

Successful abuse of scheduled tasks allows attackers to maintain long-term persistence within a compromised environment. By triggering execution at system startup or user logon, attackers ensure their malicious tools survive reboots and user sessions. If left undetected, this enables attackers to deploy additional malware, exfiltrate sensitive data, or move laterally across the network, potentially impacting all systems where these tasks are established.

## Recommendation

Deploy the provided Sigma rule to detect suspicious `schtasks.exe` invocations. Prioritize tuning for administrative software that legitimately configures tasks with these triggers to minimize false positives in the SOC.

- Enable Sysmon or Windows Security Event ID 4688 (Process Creation) logging.
- Implement the detection logic in your SIEM and tune against known-good management scripts.
- Audit existing tasks on high-value assets for entries created with the suspicious trigger types listed.
