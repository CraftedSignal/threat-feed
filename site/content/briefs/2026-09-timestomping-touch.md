---
title: Timestomping via Touch Utility
slug: 2026-09-timestomping-touch
description: Adversaries perform timestomping on Linux and macOS systems using the touch command to modify file timestamps and evade forensic detection.
date: "2026-09-18T19:13:14Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - timestomping
  - linux
  - macos
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: Timestomping is an anti-forensics technique which is used to modify the timestamps of a file.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/defense_evasion_timestomp_touch.toml
rules:
  - title: Detect Timestomping using Touch Command
    description: Detects the use of the touch command with arguments commonly used to modify file timestamps, which is a known anti-forensics technique.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.006
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
    - action: Deploy process-creation monitoring rule for 'touch' arguments.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific command line arguments used for timestomping.
  hunt_leads:
    - lead: Identify non-root processes executing 'touch' with -r, -t, -a, -m flags.
      technique_id: T1070.006
      data_needed:
        - Process command line arguments
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Timestomping is a technique used by adversaries to alter file timestamps.
---

Timestomping is an anti-forensics technique employed by adversaries to manipulate file access, modification, and change timestamps. By modifying these metadata attributes, attackers can make malicious files appear as though they were created at the same time as legitimate system files, effectively blending in with their surroundings to evade automated detection and human analysis. On Linux and macOS systems, the 'touch' command is commonly leveraged for this purpose due to its inherent ability to alter timestamp attributes through various command-line arguments.

This activity is particularly concerning for defenders because it complicates timeline analysis during incident response. Defenders must identify anomalous usage of 'touch' by non-root users and distinguish it from legitimate administrative tasks. The threat is platform-agnostic across Unix-like systems and requires granular process monitoring to detect deviations from established baselines in environment-specific workflows.

## Attack Chain

1. Initial access is established on a Linux or macOS endpoint via exploitation or credential compromise.
2. The attacker identifies a target malicious file or directory intended to be hidden or disguised.
3. The attacker assesses the timestamps of surrounding legitimate system files to determine the target timeframe.
4. The attacker executes the 'touch' utility with specific flags, such as -r (reference) or -t (timestamp), to apply the chosen metadata to the malicious file.
5. The file's timestamp is updated, effectively masking its true creation or modification time in the filesystem.
6. The attacker may move the file to a system directory to further blend in with existing binaries.
7. The attacker proceeds with additional malicious activities, such as lateral movement or data exfiltration, while the forensic trail remains obscured.

## Impact

Successful timestomping undermines the integrity of forensic investigations by invalidating file-based temporal evidence. This allows attackers to maintain persistence longer and evade detection by security teams relying on file-creation alerts. It is frequently observed in post-compromise stages across a wide variety of sectors, as it allows attackers to bypass baseline monitoring that looks for recently created or modified files.

## Recommendation

Detection engineering teams should monitor process execution logs for anomalous 'touch' activity.

- Enable process-creation logging (e.g., via Auditd or Elastic Defend) to monitor the execution of '/bin/touch'.
- Deploy the provided Sigma rule to flag instances where 'touch' is executed with flags like -t, -d, -a, -m, or -r.
- Baseline the environment to identify legitimate administrative or build-related usage of the 'touch' command and add these paths to the detection filter list.
- Review and tighten file system permissions to ensure only authorized users or service accounts can modify metadata for critical system files.
