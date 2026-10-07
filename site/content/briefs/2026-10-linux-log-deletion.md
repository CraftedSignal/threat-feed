---
title: Detection of Unauthorized Linux System Log Deletion
slug: 2026-10-linux-log-deletion
description: Adversaries may attempt to evade detection and destroy forensic evidence by deleting critical Linux system logs, requiring monitoring of file deletion events for sensitive log paths.
date: "2026-10-07T16:38:14Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - log-deletion
  - linux
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: Adversaries may delete these logs to cover their tracks, hindering forensic investigations.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: The detection rule identifies suspicious deletions of key log files, excluding benign processes.
    confidence_band: high
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/live-off-the-land-an-overview-of-unc1945
  - https://www.elastic.co/security-labs/detecting-log4j2-with-elastic-security
rules:
  - title: System Log File Deletion
    description: Detects the deletion of sensitive Linux system logs which may indicate an attempt to evade detection or destroy forensic evidence.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.002
    data_sources:
      - file_event
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the System Log File Deletion Sigma rule to detect attempts to clear audit trails
      owner: Detection Engineering
      due: 72h
      evidence: This rule identifies log deletion events that are highly indicative of evasion.
  hunt_leads:
    - lead: Search for instances of file deletions targeting /var/log/ directories in the last 30 days
      technique_id: T1070.002
      data_needed:
        - File deletion events
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Historical review can identify past evasion attempts that were not alerted on.
---

Adversaries often target system log files on Linux systems to obfuscate their activities, destroy forensic trails, and evade detection by security operations teams. This behavior is a common component of post-exploitation activity where attackers attempt to hide indicators of compromise after gaining initial access or escalating privileges. The threat involves the removal of standard system files such as authentication records, boot logs, and kernel logs located in /var/log/ or /var/run/. 

Monitoring for these deletions is essential for maintaining visibility into system integrity. However, defenders must account for legitimate system operations, such as log rotation, compression, and container management, which may legitimately interact with these files. Distinguishing malicious deletion from maintenance tasks is critical for effective alerting and preventing alert fatigue.

## Impact

Successful deletion of system logs prevents incident responders from reconstructing attacker activity, identifying the scope of a breach, or determining the duration of unauthorized access. This loss of forensic evidence can significantly increase the duration and cost of an incident response engagement.

## Recommendation

- Deploy the provided Sigma rule to monitor for deletion of sensitive log files in /var/log/ and /var/run/.
- Tune the detection logic by adding paths or process names associated with local backup tools, custom scripts, or specific log rotation utilities verified in your environment.
- Implement file integrity monitoring (FIM) or robust centralized logging to capture deletion events before the logs themselves are purged from the local host.
- Establish an automated response workflow to isolate systems where unauthorized log deletion is detected to prevent further data tampering.
