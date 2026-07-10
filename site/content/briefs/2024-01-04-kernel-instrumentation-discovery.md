---
title: Linux Kernel Instrumentation Discovery via Kprobes and Tracefs
slug: 2024-01-04-kernel-instrumentation-discovery
description: Adversaries may attempt to discover kernel instrumentation tools like Kprobes and Tracefs on Linux systems to understand the security landscape and potential detection mechanisms.
date: "2024-01-04T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - kernel
  - discovery
  - linux
  - tracefs
  - kprobes
vendors:
  - Linux
products:
  - Linux Kernel
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/discovery_kernel_instrumentation_discovery_via_kprobes_and_tracefs.toml
rules:
  - title: Detect Tracefs Directory Listing
    description: Detects attempts to list the Tracefs directory, a common technique for discovering kernel tracing capabilities.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Kprobes Directory Listing
    description: Detects attempts to list the Kprobes directory, indicating discovery of kernel probing capabilities.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This brief addresses the potential discovery of kernel instrumentation tools, specifically Kprobes and Tracefs, on Linux systems. While the provided source material does not describe active exploitation or campaigns, it highlights a potential reconnaissance activity. Understanding the presence and configuration of kernel instrumentation frameworks is crucial for adversaries aiming to evade detection or manipulate kernel-level operations. Kprobes and Tracefs are powerful tools used for dynamic kernel tracing and debugging, and their presence can provide insights into existing monitoring or security solutions. Defenders should monitor for attempts to enumerate or interact with these kernel features by unauthorized users or processes.

## Attack Chain

1. **Initial Access:** The attacker gains initial access to the system through a vulnerability or compromised credentials (not specified in source).
2. **Privilege Escalation (Optional):** If initial access is limited, the attacker attempts to escalate privileges to gain root or elevated access, necessary for kernel-level interaction (not specified in source).
3. **File System Enumeration:** The attacker lists the contents of `/sys/kernel/debug/tracing` to check for the presence of Tracefs.
4. **Kprobes Discovery:** The attacker attempts to list available kprobes by reading files in `/sys/kernel/debug/kprobes/`.
5. **Process Enumeration:** The attacker uses `ps` or similar tools to identify processes that might be using Kprobes or Tracefs, such as tracing daemons.
6. **Module Discovery:** The attacker lists loaded kernel modules (`lsmod`) to identify any tracing-related modules.
7. **Configuration Inspection:** The attacker reads configuration files related to tracing (if found) to understand how the tools are being used.
8. **Information Gathering:** The gathered information is used to tailor further attacks, evade detection, or manipulate kernel behavior.

## Impact

Successful discovery of kernel instrumentation tools can allow an attacker to understand the existing security controls and monitoring mechanisms in place. This knowledge can be leveraged to craft more sophisticated attacks that evade detection, potentially leading to data breaches, system compromise, or other malicious activities. While direct impact is dependent on subsequent actions, the reconnaissance phase significantly increases the attacker's chances of success.
