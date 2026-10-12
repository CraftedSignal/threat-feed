---
title: Detection of Malicious File Overwriting via Linux dd Command
slug: 2026-10-linux-dd-overwrite
description: Adversaries use the Linux 'dd' utility to perform destructive file overwriting, leading to data loss and system service disruption.
date: "2026-10-12T17:50:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - data-destruction
  - impact
  - linux
  - e-crime
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Adversaries often use the 'dd' command to destroy or irreversibly overwrite files, disrupting system availability and services.
    confidence_band: high
rules:
  - title: Detect Linux dd File Overwrite Activity
    description: Detects the use of the 'dd' command with output redirection flags, which is indicative of potential file destruction or data wiping.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source analytic metadata
  hunt_leads:
    - lead: Search for 'dd' command execution with output redirection to system directories
      technique_id: T1485
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: Documented adversary TTP for data destruction
  mitigation_plan:
    - priority: medium_term
      action: Restrict access to the 'dd' binary using sudoers policies to specific authorized users
      owner: IT Operations
      addresses: T1485
      evidence: General security best practice for high-risk utilities
---

This threat brief focuses on the malicious abuse of the standard Linux 'dd' utility to perform unauthorized file overwriting. Adversaries leverage this command to irreversibly destroy target files or entire partitions, significantly impacting system availability and recovery capabilities. This technique is often associated with data destruction campaigns, such as those observed in the Industroyer2 ecosystem. Defenders must monitor process execution logs for 'dd' commands containing output redirection flags ('of=') that target sensitive system files or data directories. This activity is a high-confidence indicator of destructive intent when observed outside of legitimate administrative maintenance windows.

## Impact

The abuse of the 'dd' command for file destruction can render a Linux system inoperable, resulting in critical data loss and extended downtime. Successful execution of these commands effectively deletes or corrupts files, requiring complete system re-imaging or restoration from secure offline backups, which may not be readily available for all impacted sectors.

## Recommendation

* Deploy the provided Sigma rule to detect process execution of 'dd' with output redirection flags.
* Enable Sysmon for Linux or equivalent EDR telemetry to capture full command-line arguments for all executed processes.
* Establish a baseline of authorized administrative tasks to identify and filter out legitimate usage of 'dd' by system operators.
* Monitor for suspicious process parent-child relationships where 'dd' is spawned by unexpected shell processes or web services.
