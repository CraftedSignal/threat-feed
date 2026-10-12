---
title: Detection of Linux Kernel Module Enumeration
slug: 2026-10-linux-kernel-module-enumeration
description: Detection of the kmod process enumerating kernel modules, a common discovery step used by attackers to profile systems before loading malicious rootkits or kernel-level persistence.
date: "2026-10-12T17:51:11Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - rootkit
  - linux
  - kmod
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: The analytic identifies the use of the 'kmod' process to list kernel modules on a Linux system.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Defense Evasion
    technique_id: T1014
    technique_name: Rootkit
    evidence: If confirmed malicious, this activity could allow an attacker to load kernel modules, potentially leading to privilege escalation, persistence, or other malicious actions within the system.
    confidence_band: high
rules:
  - title: Detect Linux Kernel Module Enumeration via kmod
    description: Detects the use of the kmod process with arguments indicating module listing, which may be a precursor to kernel module injection.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1014
      - T1082
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to detect kmod enumeration
      owner: Detection Engineering
      due: 72h
      evidence: Source provides analytic search logic
  hunt_leads:
    - lead: Search for kmod executions followed by insmod or modprobe
      technique_id: T1014
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Analytic story mentions Linux Rootkit
---

The kmod utility is a standard component in Linux systems used for managing kernel modules. Threat actors, particularly those deploying sophisticated malware like the XorDDos botnet or various Linux rootkits, often leverage kmod to enumerate currently loaded modules. This discovery activity is a critical precursor to identifying gaps in security controls or verifying the presence of competing malware before the attacker attempts to inject their own unauthorized kernel modules using insmod. While system administrators frequently perform this enumeration during routine maintenance or troubleshooting, its occurrence in non-standard execution contexts - or when paired with subsequent module loading commands - serves as a high-fidelity signal of potential system compromise and rootkit installation attempts.

## Attack Chain

1. Initial access is established via an exploit or stolen credentials.
2. Attacker executes reconnaissance commands to determine the current system state, including kernel version and loaded drivers.
3. Attacker executes 'kmod lsmod' or 'kmod list' to identify active kernel modules and hook points.
4. Attacker identifies a target to replace or inject a malicious module for persistence.
5. Attacker compiles or retrieves a malicious kernel module (e.g., a rootkit).
6. Attacker uses 'insmod' or 'modprobe' to load the malicious module into the kernel.
7. Attacker uses the loaded module to hide files, processes, or network connections (rootkit functionality).

## Impact

Successful exploitation allows for the installation of kernel-level rootkits, providing attackers with deep, persistent control over the operating system. This access can facilitate complete system subversion, bypass of EDR/security agents, data exfiltration, and long-term concealment of malicious activities within the kernel, making detection and removal extremely difficult.

## Recommendation

* Deploy the provided Sigma rule to detect kmod module enumeration activity within your SIEM.
* Monitor for suspicious parent-child process relationships where kmod is spawned by web servers, shells, or non-administrative service accounts.
* Establish a baseline for normal module management activity to reduce false positives from automated configuration scripts.
* Investigate any instances of kmod enumeration followed immediately by calls to 'insmod' or 'modprobe' for unknown or unsigned files.
