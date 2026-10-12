---
title: Abuse of forfiles.exe for Indirect Command Execution
slug: 2026-10-forfiles-abuse
description: Attackers utilize the Windows built-in utility 'forfiles.exe' to execute commands against multiple files, a technique leveraged by the Prestige ransomware to facilitate post-exploitation file enumeration and malicious activity.
date: "2026-10-12T18:08:33Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - post-exploitation
  - ransomware
  - windows
  - living-off-the-land
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: forfiles.exe can be abused to execute commands on multiple files, a technique used by ransomware like Prestige.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: The following analytic detects excessive usage of the forfiles.exe process, which is often indicative of post-exploitation activities.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/forfiles
  - https://www.microsoft.com/en-us/security/blog/2022/10/14/new-prestige-ransomware-impacts-organizations-in-ukraine-and-poland/
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1202/T1202.yaml
rules:
  - title: Detect Excessive Forfiles Process Execution
    description: Detects 20 or more executions of forfiles.exe within a 1-minute window, indicative of batch processing for malicious purposes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1202
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
    - action: Deploy the Sigma rule to monitor for excessive forfiles.exe usage
      owner: Detection Engineering
      due: 48h
      evidence: Source analytic logic requires process count monitoring
  hunt_leads:
    - lead: Search for processes spawning more than 20 forfiles.exe instances per minute
      technique_id: T1202
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: Source search defines 20 count as the anomaly threshold
---

The built-in Windows utility `forfiles.exe` is frequently abused by attackers to perform indirect command execution. By selecting specific files and executing a command on each, attackers can systematically interact with data on a compromised system. This technique is often seen during the post-exploitation phase, where threat actors enumerate files, execute secondary payloads, or prepare for data exfiltration. Notably, the Prestige ransomware has been documented using this method to facilitate its operations. Defenders should focus on process execution patterns where `forfiles.exe` is invoked repeatedly in a short duration, as this deviates significantly from standard administrative usage and is a strong indicator of automated post-exploitation activity.

## Impact

Successful abuse of this technique allows attackers to automate interactions with the filesystem, significantly increasing the efficiency of data exfiltration and the deployment of secondary ransomware components. This activity has been observed in attacks affecting organizations in Eastern Europe, posing a severe risk to data integrity and business continuity if allowed to progress to full encryption or exfiltration stages.

## Recommendation

Detection engineering teams should monitor high-frequency process creation events for `forfiles.exe`.

* Deploy the provided Sigma rule to detect excessive usage of `forfiles.exe` by tracking process execution counts within a 1-minute window.
* Enable Sysmon Event ID 1 or Windows Security Event 4688 to capture comprehensive command-line and parent process metadata.
* Configure SIEM analytics to alert when the count of `forfiles.exe` executions per host exceeds a baseline threshold (e.g., 20 processes per minute).
