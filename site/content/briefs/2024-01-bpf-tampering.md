---
title: Linux BPF Program Tampering for Defense Evasion
slug: 2024-01-bpf-tampering
description: Attackers can manipulate or tamper with Berkeley Packet Filter (BPF) programs on Linux systems to evade detection or analysis by security tools that rely on BPF for monitoring and security enforcement.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - bpf
  - linux
  - kernel
vendors:
  - Linux
products:
  - Linux Kernel
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_bpf_program_tampering.toml
rules:
  - title: Detect BPF Program Loading by Unexpected Processes
    description: Detects when a process not typically associated with BPF program management attempts to load a BPF program, which could indicate malicious tampering.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Modification of BPF Related Files
    description: Detects attempts to modify BPF related files, potentially indicating tampering.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

BPF program tampering is a defense evasion technique where malicious actors modify or interfere with BPF programs running on a Linux system. BPF programs are often used by security tools for monitoring, auditing, and intrusion detection. By compromising these programs, attackers can effectively blind security solutions, allowing malicious activities to go undetected. This is particularly concerning in modern Linux environments where BPF is increasingly used for advanced security functionalities. Successful tampering can lead to prolonged persistence, lateral movement, and data exfiltration without triggering security alerts. The scope of impact can range from individual hosts to entire server infrastructures.

## Attack Chain

1. **Initial Access:** The attacker gains initial access to the system, potentially through exploiting a vulnerability or using stolen credentials.
2. **Privilege Escalation:** If necessary, the attacker escalates privileges to root or a similar level of access required to manipulate BPF programs.
3. **Locate BPF Programs:** The attacker identifies the BPF programs used by security tools, such as intrusion detection systems or endpoint detection and response (EDR) agents.
4. **Modify BPF Program Code:** The attacker modifies the code of the BPF programs to disable or bypass security checks and monitoring functions. This could involve injecting malicious code or removing existing security filters.
5. **Load Modified BPF Program:** The attacker loads the modified BPF program into the kernel, replacing the original program. This might require specific system calls or tools.
6. **Verify Tampering:** The attacker verifies that the tampering is successful by testing whether the modified BPF program still performs its intended function, or by observing the absence of security alerts when performing malicious actions.
7. **Execute Malicious Actions:** The attacker performs malicious actions, such as lateral movement, data exfiltration, or malware installation, knowing that the compromised BPF program will not trigger alerts.

## Impact

Successful BPF program tampering can lead to a significant compromise of system security. Victims may experience data breaches, financial loss, or reputational damage due to undetected malicious activities. The attack can disable critical security controls, giving attackers free reign within the compromised system. The number of potential victims is broad, ranging from individual Linux servers to large-scale enterprise deployments utilizing BPF-based security solutions.
