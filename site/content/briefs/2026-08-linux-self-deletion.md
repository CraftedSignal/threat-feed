---
title: Detecting Linux Defense Evasion via Executable Self-Deletion
slug: 2026-08-linux-self-deletion
description: Adversaries targeting Linux systems often execute payloads from ephemeral directories and immediately delete the binary to evade detection and hinder forensic investigation.
date: "2026-08-20T13:05:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - linux
  - file-integrity
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: Detects a process execution followed by immediate self-deletion, a common technique used by adversaries to remove traces of their activity on the system.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_execution_followed_by_self_deletion.toml
rules:
  - title: Detect Linux Process Execution Followed by Self-Deletion
    description: Detects a process execution from an ephemeral location followed by the immediate deletion of the binary, a common technique for hiding malicious artifacts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for process execution followed by deletion in /tmp or /dev/shm.
      owner: Detection Engineering
      due: 72h
      evidence: This rule identifies a common evasion technique utilized by adversaries on Linux.
---

Adversaries targeting Linux environments frequently employ defense evasion techniques to minimize their footprint and complicate incident response. A common behavior observed in both malware and targeted attacks is the execution of a malicious payload from a temporary or ephemeral location, such as /tmp, /dev/shm, or memory-mapped files (memfd), followed by the immediate deletion of the executable file. By removing the file after the process has successfully started, the attacker prevents investigators from easily recovering the binary for static analysis or signature generation. This behavior is a high-fidelity indicator of malicious activity, as legitimate system binaries rarely exhibit this pattern of self-deletion within a short window after execution.

## Impact

Successful execution of this technique allows attackers to maintain persistence or conduct malicious operations with a significantly reduced disk signature. This evasion tactic hinders the collection of artifacts needed for root cause analysis and indicator development, potentially allowing an actor to remain undetected for longer periods during an intrusion.

## Recommendation

Detection engineering teams should implement monitoring for process-file interaction sequences in ephemeral directories.

- Deploy the provided Sigma rule to identify process execution events followed by file deletion events within a short timeframe.
- Prioritize auditing of temporary directories (/tmp, /var/tmp, /dev/shm) for execution-from-disk activities.
- Enable filesystem monitoring via EDR to capture file deletion events correlated with parent process entity IDs.
