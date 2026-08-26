---
title: Detection of Malicious Binfmt Configuration File Creation
slug: 2026-08-binfmt-persistence
description: Detection rule monitoring for the creation of binfmt configuration files which can be abused by threat actors to execute arbitrary code or maintain persistence on Linux systems.
date: "2026-08-26T13:55:13Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - linux
  - endpoint-security
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: By creating a malicious binfmt configuration file, threat actors can execute a backdoor script or command on the target system.
    confidence_band: high
references:
  - https://dfir.ch/posts/today_i_learned_binfmt_misc/
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_binfmt_configuration_file_creation.toml
rules:
  - title: Detect Binfmt Configuration File Creation
    description: Detects the creation of configuration files or direct registration of handlers within binfmt directories, potentially indicating persistence attempts.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1546
    data_sources:
      - file_event
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for suspicious binfmt modifications
      owner: Detection Engineering
      due: 72h
      evidence: Rule provided in source content
  hunt_leads:
    - lead: Audit existing files in /etc/binfmt.d/ and /usr/lib/binfmt.d/ for unauthorized entries
      technique_id: T1546
      data_needed:
        - Filesystem contents
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source describes configuration files as the mechanism for persistence
---

The binfmt_misc kernel module in Linux is designed to allow the kernel to recognize and execute arbitrary binary formats by associating them with a specific user-space interpreter. While intended for legitimate functionality such as cross-platform execution (e.g., QEMU static binaries) or language-specific interpreters, this mechanism is a potent vector for threat actors. By creating a malicious configuration file within designated directories or directly writing to the /proc/sys/fs/binfmt_misc/register interface, an attacker can designate a malicious script or backdoor as the handler for specific file types. Whenever a file matching that format is accessed, the kernel automatically executes the attacker-controlled handler, facilitating persistence or privilege escalation. This brief details detection logic for identifying anomalous file creation events within these sensitive paths.

## Impact

Successful abuse of the binfmt_misc mechanism allows threat actors to establish stealthy persistence, as the execution of the malicious handler is triggered by the kernel upon interaction with target file types. This technique can lead to arbitrary code execution with the privileges of the binfmt registration process or the kernel, potentially resulting in full system compromise, exfiltration of sensitive data, or deep-seated backdoors that survive standard reboots.

## Recommendation

Deploy the provided detection logic to monitor all file creation and write operations directed at binfmt-related configuration paths. 

- Enable file system auditing (e.g., auditd, eBPF-based monitoring, or Elastic Defend) for the following directories: /etc/binfmt.d/, /run/binfmt.d/, /usr/lib/binfmt.d/, and /proc/sys/fs/binfmt_misc/.
- Investigate any process other than systemd-binfmt that writes to these paths, as these are high-fidelity indicators of potential persistence attempts.
- Review existing binfmt configurations in your environment to establish a baseline of legitimate handlers and remove unauthorized entries.
