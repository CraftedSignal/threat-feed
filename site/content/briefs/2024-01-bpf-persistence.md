---
title: Linux BPF Program or Map Load for Persistence
slug: 2024-01-bpf-persistence
description: Attackers can leverage Linux's Berkeley Packet Filter (BPF) functionality to establish persistence by loading malicious programs or maps, allowing for stealthy and persistent code execution within the kernel.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - linux
  - bpf
vendors:
  - Linux
products:
  - Linux Kernel
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_bpf_program_or_map_load.toml
rules:
  - title: Detect BPF Program Load via bpftool
    description: Detects the execution of `bpftool` to load a BPF program, which could indicate malicious persistence activity.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.001
    data_sources:
      - process_creation
      - linux
  - title: Detect BPF Map Creation via bpftool
    description: Detects the execution of `bpftool` to create a BPF map, which could be used for malicious purposes.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1543.001
    data_sources:
      - process_creation
      - linux
  - title: Detect suspicious file operations in /sys/fs/bpf/
    description: Detects file creation and writing under the /sys/fs/bpf/ directory, where BPF programs and maps reside.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1543.001
    data_sources:
      - file_event
      - linux
rules_count: 3
---

The use of Berkeley Packet Filter (BPF) programs and maps for persistence in Linux systems is an advanced technique that allows attackers to execute code within the kernel space. This approach provides a high level of stealth, as BPF programs can operate without being easily detected by traditional user-space monitoring tools. While the exact mechanisms and specific tools employed in real-world attacks are not detailed in this document, the potential for this type of persistence is significant. Defenders should be aware of the potential for malicious BPF programs or maps being loaded onto systems as a means of maintaining unauthorized access, modifying system behavior, or hiding malicious activities. Given the low-level nature of this technique, it can be challenging to detect and requires a deep understanding of the Linux kernel and BPF subsystem.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access to the target system through unspecified means (e.g., exploiting a vulnerability, social engineering).
2.  **Privilege Escalation:** The attacker escalates privileges to root or a user with sufficient permissions to load BPF programs or maps. This might involve exploiting kernel vulnerabilities or misconfigurations.
3.  **BPF Program/Map Creation:** The attacker crafts a malicious BPF program or map designed to execute specific malicious actions or intercept system calls.
4.  **BPF Program/Map Loading:** The attacker loads the malicious BPF program or map into the kernel using tools like `bpftool` or custom loaders, potentially hiding the program's purpose through obfuscation.
5.  **Hooking and Execution:** The loaded BPF program hooks into specific kernel functions or events, triggering the execution of malicious code whenever those events occur. This could involve network traffic inspection, system call interception, or other kernel-level operations.
6.  **Persistence:** The attacker ensures the BPF program or map persists across reboots by configuring it to load automatically at system startup. This might involve modifying system configuration files or using systemd services.
7.  **Concealment:** The attacker takes steps to conceal the loaded BPF program or map from detection. This could include hiding the program's file on disk or manipulating kernel data structures to avoid detection by monitoring tools.
8.  **Malicious Activity:** The loaded BPF program or map executes its malicious purpose, such as stealing data, injecting code, or establishing a backdoor for remote access.

## Impact

Successful exploitation of BPF for persistence can lead to complete system compromise, allowing attackers to execute arbitrary code within the kernel. This can result in data theft, system instability, or the establishment of a persistent backdoor that is difficult to detect and remove. Due to the stealthy nature of this technique, it can allow attackers to maintain long-term access to compromised systems. The impact is critical, as kernel-level access bypasses many standard security controls.
