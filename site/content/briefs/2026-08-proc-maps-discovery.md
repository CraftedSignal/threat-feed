---
title: Suspicious Linux /proc/*/maps File Discovery
slug: 2026-08-proc-maps-discovery
description: Adversaries leverage read access to /proc/*/maps files on Linux systems to perform memory mapping reconnaissance, a precursor to code injection, process hijacking, and credential harvesting.
date: "2026-08-24T15:48:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - linux
  - discovery
  - memory-reconnaissance
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1057
    technique_name: Process Discovery
    evidence: Adversaries may read a process's memory map to identify memory addresses for code injection or process hijacking.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Attackers may read a process's memory map to identify memory addresses for code injection or process hijacking.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/discovery_proc_maps_read.toml
  - https://github.com/arget13/DDexec
rules:
  - title: Suspicious /proc/maps Discovery
    description: Detects suspicious reads of the /proc/*/maps file using common command-line utilities, indicating potential memory reconnaissance.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1003.007
      - T1057
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy rule to detect /proc/*/maps access
      owner: Detection Engineering
      due: 72h
      evidence: Rule defined in brief
  mitigation_plan:
    - priority: medium_term
      action: Enforce least privilege for non-root users accessing /proc
      owner: IT Operations
      addresses: T1003.007
      evidence: General security best practices for /proc filesystem
---

Monitoring access to the /proc/[pid]/maps file is critical for detecting memory-based reconnaissance on Linux systems. This pseudo-file provides a comprehensive map of a process's memory layout, including addresses, permissions, and backing files. Sophisticated attackers exploit this information to identify memory locations suitable for code injection or to facilitate process hijacking. Furthermore, the information contained in memory maps is often leveraged during the credential dumping phase, where adversaries search for sensitive data residing within process memory.

The activity is frequently observed during the early stages of an intrusion to gain environmental awareness. While legitimate system diagnostics, security agents, and debugging tools also access these files, malicious use typically involves common command-line utilities (such as cat, grep, or awk) executed from interactive shells or unauthorized automated scripts. Defenders must baseline legitimate administrative and security software in their environment to minimize noise when alerting on this behavior.

## Impact

Successful reconnaissance of process memory maps provides adversaries with the necessary context to perform advanced exploitation techniques. If attackers effectively map process memory, they can bypass security controls to conduct reliable process injection, execute fileless payloads, or target specific memory segments containing plaintext credentials or cryptographic material. This technique is often used in lateral movement and persistence phases of an attack.

## Recommendation

- Deploy the Sigma rules below to monitor for process execution patterns accessing the /proc filesystem.
- Establish a comprehensive allowlist for known security tools, system diagnostics, and administrative maintenance scripts that legitimately interface with /proc/*/maps.
- Implement strict process execution policies to limit which user-mode applications can trigger file-read operations on sensitive /proc entries.
- Conduct regular memory analysis on high-value systems to detect evidence of injected code or unauthorized modifications identified via memory map reconnaissance.
