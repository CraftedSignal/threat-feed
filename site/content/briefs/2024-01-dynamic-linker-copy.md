---
title: Linux Dynamic Linker Copy and Shared Object Creation
slug: 2024-01-dynamic-linker-copy
description: This brief outlines detection strategies for Linux systems where the dynamic linker binary is copied and a shared object file is created, a technique used by malware to inject malicious shared objects by patching the dynamic linker.
date: "2024-01-09T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - linux
  - dynamic-linker
  - shared-object
vendors:
  - Linux
products:
  - Linux operating system
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
references:
  - https://www.intezer.com/blog/incident-response/orbit-new-undetected-linux-threat/
rules:
  - title: Dynamic Linker Copy and Shared Object Creation
    description: Detects the copying of the Linux dynamic linker and subsequent creation of shared object files, indicative of potential dynamic linker hijacking.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1574.006
    data_sources:
      - process_creation
      - linux
  - title: Dynamic Linker Preload Modification
    description: Detects modifications to the /etc/ld.so.preload file, often used to hijack the dynamic linker.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1574.006
    data_sources:
      - file_event
      - linux
rules_count: 2
---

This brief addresses a persistence technique where attackers copy the Linux dynamic linker binary (ld-linux-x86-64.so.2) and subsequently create or modify shared object files (.so), often after modifying `/etc/ld.so.preload`.  This activity has been observed in Linux malware campaigns, where attackers aim to inject and preload malicious shared objects.  The dynamic linker is a crucial component for loading shared libraries, making it a valuable target for attackers seeking to establish persistence and execute malicious code. Recent malware, such as Orbit, has used this technique, making it critical to detect this behavior. The detection focuses on identifying processes involved in copying the dynamic linker, modifications to `/etc/ld.so.preload`, and the creation of suspicious shared object files.

## Attack Chain

1. An attacker gains initial access to a Linux system, possibly through exploitation of a vulnerability or compromised credentials.
2. The attacker uses `cp`, `rsync`, or `mv` to create a backup copy of the dynamic linker (`/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2`, `/lib64/ld-linux-x86-64.so.2`, `/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2`, or `/usr/lib64/ld-linux-x86-64.so.2`).
3. The attacker modifies the original dynamic linker binary to inject malicious code or alter its functionality.
4. The attacker creates or modifies a shared object (.so) file containing malicious code.
5. The attacker modifies the `/etc/ld.so.preload` file to include the path to the malicious shared object. This ensures that the malicious shared object is loaded by every program that uses the dynamic linker.
6. The attacker executes a program that relies on the dynamic linker, triggering the loading of the malicious shared object.
7. The malicious shared object executes its payload, potentially leading to code execution, privilege escalation, or data exfiltration.
8. The attacker maintains persistence by ensuring the malicious shared object continues to be loaded on system startup or during regular program execution.

## Impact

Successful execution of this attack allows the attacker to achieve persistence on the compromised Linux system. This can lead to long-term control over the system, allowing the attacker to steal sensitive data, install backdoors, or use the system as a launching point for further attacks within the network. The Intezer report referenced in the brief highlights the use of this technique by the Orbit malware, demonstrating its real-world impact. The targeted sectors can be broad, depending on the attacker's objectives, and can include any organization relying on Linux systems for critical infrastructure or sensitive data storage.

## Recommendation

*   Deploy the "Dynamic Linker Copy and Shared Object Creation" Sigma rule to your SIEM to detect suspicious file copy operations and shared object creation activities.
*   Monitor `/etc/ld.so.preload` file modifications using a file integrity monitoring (FIM) system and correlate with process creation events related to `cp`, `rsync`, and `mv`.
*   Enable process monitoring with command-line argument logging to capture the full command executed by processes like `cp`, `rsync`, and `mv`. This will help identify cases where the dynamic linker is being targeted.
*   Investigate any alerts triggered by the Sigma rule and analyze the involved processes, files, and user accounts to determine if malicious activity is present. Reference the investigation steps in the rule's `note` field.
*   Monitor for the creation of shared objects (.so files) in unusual directories and correlate these events with modifications to `/etc/ld.so.preload`.
