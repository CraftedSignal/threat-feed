---
title: Detection of Linux 'At' Utility Abuse for Persistence
slug: 2026-10-linux-at-persistence
description: Attackers can abuse the Linux 'at' or 'atd' utilities to maintain unauthorized access or escalate privileges by scheduling malicious tasks.
date: "2026-10-12T17:47:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - linux
  - persistence
  - schedule-task
  - edr
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: The following analytic detects the execution of the 'At' application in Linux, which can be used by attackers to create persistence entries on a compromised host.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor 'at' and 'atd' process execution.
      owner: Detection Engineering
      due: 24h
      evidence: Source document identifies 'at' application execution as a mechanism for persistence.
  hunt_leads:
    - lead: Search for 'at' or 'atd' process executions occurring outside of known administrative time windows or from unexpected parent processes.
      technique_id: T1053.002
      data_needed:
        - Process creation logs (EDR/Sysmon)
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: The 'at' utility can be abused for unauthorized persistence.
---

The 'at' and 'atd' utilities in Linux environments are legitimate tools designed for scheduling tasks to run at specific future times. Threat actors frequently abuse these utilities to establish persistence or facilitate privilege escalation on compromised hosts. By leveraging the 'at' daemon, an attacker can ensure that malicious payloads, backdoors, or system modifications execute automatically without requiring further interaction. This behavior is particularly dangerous as it operates within the context of system automation, often blending in with standard administrative operations. Defenders should focus on monitoring the execution of 'at' or 'atd' binaries, especially when invoked by unusual parent processes or unexpected user accounts. Because these utilities are common, effective detection requires distinguishing between legitimate system automation and anomalous usage patterns that deviate from established baselines.

## Attack Chain

1. Initial access is gained on the Linux host (e.g., via web shell or exploitation of a service).
2. The attacker identifies the presence of the 'at' or 'atd' utility on the target system.
3. The attacker writes a malicious payload or script to a temporary directory (e.g., /tmp).
4. The attacker uses the 'at' command to schedule the execution of the malicious script at a future time.
5. The 'atd' daemon manages the job queue and monitors the system clock.
6. Upon reaching the scheduled time, the 'atd' daemon executes the script with the privileges of the user who scheduled the job.
7. The malicious script runs, providing the attacker with persistent access or elevated command execution.

## Impact

Successful abuse of the 'at' utility can lead to long-term persistence, unauthorized lateral movement, and privilege escalation. If left undetected, this mechanism allows attackers to maintain a foothold on critical infrastructure, facilitating ongoing data theft, potential ransomware deployment, or unauthorized system configuration changes.

## Recommendation

- Deploy the provided Sigma rule to monitor for 'at' or 'atd' process creation across all Linux endpoints.
- Establish a baseline of known-good administrative automation scripts that use the 'at' utility to reduce false positives.
- Implement strict process execution logging via Sysmon for Linux or equivalent EDR telemetry, focusing on the parent process of 'at' and 'atd' invocations.
- Audit scheduled jobs periodically to identify and remove unauthorized or suspicious entries.

## Rules

- title: "Detect Linux At Application Execution"
 description: "Detects the execution of the 'at' or 'atd' applications which can be used to schedule malicious tasks for persistence."
 logsource:
 category: "process_creation"
 product: "linux"
 detection:
 selection:
 Image|endswith:
 - "/at"
 - "/atd"
 ParentImage|endswith:
 - "/at"
 - "/atd"
 condition: selection
 level: "medium"
 tags:
 - "attack.persistence"
 - "attack.privilege-escalation"
 - "attack.t1053.002"
 tests:
 positive:
 - name: "Direct execution of at utility"
 data:
 - Image: "/usr/bin/at"
 ParentImage: "/usr/bin/bash"
 negative:
 - name: "Common system process"
 data:
 - Image: "/usr/bin/sshd"
 ParentImage: "/usr/bin/systemd"
 falsepositives:
 - "Legitimate administrative tasks scheduled by operators or existing automation scripts."
 handoff:
 detection_confidence: "medium"
 required_telemetry:
 - log_source: "Sysmon for Linux"
 event_or_channel: "Event ID 1"
 required_fields:
 - "Image"
 - "ParentImage"
 - "CommandLine"
 availability: "available"
 notes: "Requires Sysmon for Linux or equivalent EDR process auditing."
 validation:
 status: "needs_environment_validation"
 steps:
 - "Run 'echo \"id\" | at now + 1 minute' in a controlled lab environment."
 expected_telemetry: "Sysmon Event ID 1 showing /usr/bin/at execution."
 pass_criteria: "Detection rule identifies the 'at' process."
 atomic_reference: "Atomic Red Team T1053.002"
 tuning:
 - source: "Automation scripts"
 guidance: "Filter based on known service accounts or parent process paths that are part of legitimate maintenance."
 suggested_owner: "Detection Engineering"
