---
title: Suspicious QEMU Execution on Windows
slug: 2024-01-suspicious-qemu-execution
description: Detects the execution of QEMU with the -nographic flag and an image file on Windows systems, a technique used for persistence and initial access by installing a rogue Linux virtual machine.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - qemu
  - virtualization
  - persistence
  - linux
  - windows
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - QEMU
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1564
    technique_name: Hide Artifacts
references:
  - https://www.securonix.com/blog/crontrap-emulated-linux-environments-as-the-latest-tactic-in-malware-staging/
  - https://www.bleepingcomputer.com/news/security/windows-infected-with-backdoored-linux-vms-in-new-phishing-attacks/
rules:
  - title: Suspicious QEMU Execution
    description: Detects QEMU execution with -nographic flag and image file.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1204.002
      - T1564.006
    data_sources:
      - process_creation
      - windows
  - title: QEMU Process Description Match
    description: Detects QEMU execution based on process description.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1204.002
      - T1564.006
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief focuses on the suspicious execution of QEMU (Quick Emulator) on Windows systems. Attackers are leveraging QEMU, a legitimate open-source machine emulator and virtualizer, to establish persistence and potentially gain initial access. By executing QEMU with the `-nographic` flag along with an image file, the virtual machine operates in the background without a graphical display, making it less conspicuous to the user. This technique has been observed as a method to deploy rogue Linux virtual machines, which can then be used for various malicious activities. The securonix.com blog and bleepingcomputer.com news have reported on this technique being used in the wild.

## Attack Chain

1.  **Initial Access:** An attacker gains initial access to a Windows system, potentially through social engineering or exploiting existing vulnerabilities.
2.  **QEMU Installation (or Existing):** The attacker either installs QEMU (if not already present) or leverages an existing installation.
3.  **Image File Placement:** A malicious Linux image file (`.img`) is placed on the compromised system.
4.  **Persistence via Scheduled Task/Service:** The attacker creates a scheduled task or Windows service to execute QEMU automatically upon system startup or at specific intervals.
5.  **QEMU Execution:** The scheduled task or service executes QEMU with the `-nographic` flag and points to the malicious Linux image file. Example command: `qemu-system-x86_64.exe -nographic -hda malicious.img`.
6.  **Rogue VM Initialization:** The Linux virtual machine boots in the background without any user interaction.
7.  **Malicious Activity within VM:** The rogue VM executes malicious scripts, downloads additional payloads, or establishes communication with a command-and-control (C2) server.
8.  **Lateral Movement/Data Exfiltration:** The attacker leverages the compromised VM as a staging point for lateral movement within the network or for exfiltrating sensitive data.

## Impact

Successful exploitation allows attackers to establish persistent access to a compromised Windows system, potentially bypassing traditional security measures. The rogue Linux virtual machine provides a hidden environment for executing malicious activities, such as installing backdoors, conducting reconnaissance, or launching further attacks against the internal network. This can lead to data theft, system compromise, and significant disruption of business operations.

## Recommendation

*   Deploy the Sigma rule "Suspicious QEMU Execution" to detect QEMU processes running with the `-nographic` flag and an image file (see `rules`).
*   Monitor process execution logs for command lines containing "qemu" and "-nographic" to identify potential rogue VM deployments.
*   Investigate any scheduled tasks or services that launch QEMU with the `-nographic` flag to determine their legitimacy.
*   Review and whitelist approved systems that legitimately run QEMU with the -nographic flag to reduce false positives as noted in the `known_false_positives` section.
*   Enable Sysmon Event ID 1 logging to capture process creation events, providing the data needed for the Sigma rules (see `data_source`).
