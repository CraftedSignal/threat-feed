---
title: Suspicious Kernel Module Load from Unusual Location (Linux)
slug: 2024-01-09-kernel-module-load-from-unusual-location
description: This alert detects the loading of Linux kernel modules from non-standard directories, potentially indicating malicious persistence or rootkit activity.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kernel-module
  - persistence
  - rootkit
  - linux
vendors:
  - Linux
products:
  - Kernel
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_kernel_module_load_from_unusual_location.toml
rules:
  - title: Detect Kernel Module Load from Suspicious Path
    description: Detects the loading of kernel modules from non-standard or suspicious directories.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - linux
  - title: Detect modprobe with unusual module path
    description: Detects the use of modprobe to load modules from non-standard paths.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This detection identifies instances where Linux kernel modules are loaded from locations outside the typical system directories (e.g., /lib/modules). Kernel modules are typically loaded from specific directories managed by the system, and loading from other locations can indicate an attempt to hide malicious code or persist unauthorized functionality within the kernel. This behavior is often associated with rootkits or advanced persistent threats (APTs) seeking to maintain a low profile on compromised systems. This detection is crucial for identifying potentially malicious kernel-level activity that bypasses normal security controls.

## Attack Chain

1.  Initial access is achieved through exploitation of a vulnerability or compromised credentials, allowing an attacker to gain privileged access to the system.
2.  The attacker uploads or compiles a malicious kernel module to a non-standard directory, such as /tmp/ or /var/tmp/.
3.  Using the `insmod` or `modprobe` command, the attacker attempts to load the malicious kernel module into the running kernel.
4.  The system logs an event related to the kernel module load attempt, including the path from where the module is loaded.
5.  The malicious kernel module executes its intended payload, potentially hooking system calls or modifying kernel data structures.
6.  The attacker leverages the loaded module for persistence, ensuring the malicious code is loaded automatically on subsequent reboots.
7.  The attacker can use the module to hide processes, files, or network connections, further concealing their activity.

## Impact

A successful attack using a malicious kernel module can result in complete system compromise. Attackers can use this technique to bypass security controls, establish persistent access, and hide their activities from standard monitoring tools. This can lead to data theft, system instability, or the deployment of ransomware. The compromised kernel can also be used to infect other systems on the network.
