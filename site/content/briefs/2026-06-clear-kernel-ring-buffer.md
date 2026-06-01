---
title: Attempt to Clear Kernel Ring Buffer via dmesg
slug: 2026-06-clear-kernel-ring-buffer
description: The rule detects attempts to clear the kernel ring buffer on Linux systems using the `dmesg` command with options like `-c`, `-C`, `--clear`, or `--read-clear` to evade detection.
date: "2026-06-01T12:06:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - kernel-ring-buffer
  - linux
vendors:
  - Elastic
products:
  - Elastic Defend
  - Elastic Endgame
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_clear_kernel_ring_buffer.toml
rules:
  - title: Detect Kernel Ring Buffer Cleared via dmesg
    description: Detects clearing the kernel ring buffer using the `dmesg` command with specific arguments.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070.002
    data_sources:
      - process_creation
      - linux
  - title: Detect Kernel Ring Buffer Cleared via dmesg - alternative path
    description: Detects clearing the kernel ring buffer using the `dmesg` command with specific arguments in /bin
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070.002
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This detection rule identifies attempts to clear the kernel ring buffer on Linux systems, a tactic often employed by attackers to evade detection after installing malicious Linux Kernel Modules (LKMs). The kernel ring buffer stores system messages, including those related to LKM installation and activity. By clearing this buffer using the `dmesg` command with specific arguments, attackers aim to remove traces of their activities, hindering forensic investigations and incident response. This technique is often associated with intrusions leveraging kernel-level rootkits to maintain persistence on compromised hosts. The rule monitors for the execution of the `dmesg` command with arguments used to clear the buffer, providing a high-fidelity signal of potential defense evasion.

## Attack Chain

1.  The attacker gains initial access to the Linux system, potentially through exploiting a vulnerability or using compromised credentials.
2.  The attacker escalates privileges to root, if necessary, to perform kernel-level operations.
3.  The attacker installs a malicious Linux Kernel Module (LKM) to establish persistence or perform other malicious activities.
4.  The attacker executes the `dmesg` command with the `-c`, `-C`, `--clear`, or `--read-clear` arguments. This command clears the kernel ring buffer, removing recent system messages.
5.  The system logs record the execution of the `dmesg` command.
6.  The attacker may further tamper with other logs or system configurations to eliminate additional evidence of their presence.
7.  The attacker maintains persistent access through the installed LKM, potentially performing data exfiltration or other malicious activities.
8.  The attacker's objective is to maintain a hidden presence and continue malicious activities without detection.

## Impact

Successful clearing of the kernel ring buffer can significantly hinder incident response efforts. It can obscure the installation and activities of malicious LKMs, making it difficult to identify the root cause of a compromise and assess the extent of the damage. This evasion tactic allows attackers to maintain a persistent presence on the compromised system, potentially leading to long-term data theft, system disruption, or other malicious outcomes.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM to detect attempts to clear the kernel ring buffer via `dmesg`.
*   Investigate any alerts triggered by the Sigma rules, focusing on the user account and processes involved.
*   Monitor for the installation and modification of Linux kernel modules (LKMs) to detect unauthorized kernel-level changes.
*   Review and update access controls and permissions to limit the ability to execute commands like `dmesg -c` to authorized users only.
*   Enable Elastic Defend, Elastic Endgame, Auditd Manager, Crowdstrike, and SentinelOne data ingestion to enable the detection rule from the source advisory.
