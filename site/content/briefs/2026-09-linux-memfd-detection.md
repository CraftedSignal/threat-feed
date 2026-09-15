---
title: Detection of Fileless Execution via memfd_create on Linux
slug: 2026-09-linux-memfd-detection
description: This brief details a detection strategy for identifying potential fileless execution on Linux platforms by monitoring the memfd_create syscall for anomalous process lineage and execution paths.
date: "2026-09-15T18:58:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - linux
  - defense-evasion
  - fileless-execution
  - edr
  - process-lineage
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1620
    technique_name: Reflective Code Loading
    evidence: This can indicate fileless execution using memfd-backed executables.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
    evidence: An attacker can decrypt an ELF payload into an anonymous memory file and execute it through /proc/self/fd.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1106
    technique_name: Native API
    evidence: This rule detects a memfd_create syscall event on Linux.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_fileless_execution_via_unusual_memfd_create.toml
rules:
  - title: Potential Fileless Execution via Unusual memfd Create Call
    description: Detects memfd_create syscall events where the combination of host, parent process, and executable path has not been seen before, indicating potential fileless execution.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1055.009
      - T1620
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the rule to monitor for anomalous memfd_create activity.
      owner: Detection Engineering
      due: 72h
      evidence: Source provides rule logic to identify anomalous memory-backed execution.
  enrichment_needed:
    - item: Known-good baselines
      owner: SOC
      reason: Necessary to reduce noise from legitimate system tools.
      evidence: Rule investigation guide suggests comparing binary metadata against approved inventories.
  hunt_leads:
    - lead: Search for processes executing from /proc/*/fd/*.
      technique_id: T1620
      data_needed:
        - Process creation events
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source documentation notes execution through /proc/self/fd as a primary indicator.
---

This brief addresses the risk of fileless execution on Linux systems using the `memfd_create` system call. The technique allows an attacker to decrypt an ELF payload into an anonymous, memory-backed file, effectively bypassing traditional disk-based security controls. By executing the payload directly from memory - often via `/proc/self/fd` - malicious actors can execute code without leaving persistent disk artifacts.

Defenders can detect this behavior by monitoring for `memfd_create` events where the combination of host ID, parent executable, and process executable path has not been previously observed. This approach focuses on behavioral anomalies, helping to distinguish between legitimate system utility usage (such as JIT compilation or software self-updates) and malicious reflective code loading. Because this detection relies on baseline behavioral analysis, organizations should tune these detections against their specific Linux environment to reduce false positives from routine administrative or runtime-specific activity.

## Impact

Successful fileless execution enables attackers to maintain stealth, evade host-based security tools, and minimize the footprint of their malicious operations. If used by an adversary, this technique can lead to long-term persistence, credential theft, and unauthorized command execution. Impacts are broad, potentially affecting any enterprise Linux environment, containerized workload, or cloud-native infrastructure that lacks specific behavioral monitoring for process ancestry and memory-backed execution.

## Recommendation

- Deploy behavioral monitoring for the `memfd_create` syscall on all critical Linux endpoints using EDR capabilities.
- Implement the provided detection logic to baseline process lineage and alert on new, unseen combinations of parent/child executables involving memfd-backed execution.
- Establish a process for triaging alerts by reconstructing process ancestry and examining `/proc/<pid>/exe` mappings before process termination.
- Apply host-based sandboxing, such as systemd unit sandboxing or seccomp profiles, to limit the ability of non-privileged services to execute code from memory-backed or temporary filesystem paths.
- Regularly audit and baseline software that legitimately requires `memfd_create` functionality (e.g., container runtimes, language JIT compilers) to prevent alert fatigue.
