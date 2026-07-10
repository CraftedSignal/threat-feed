---
title: Linux Kernel Module Load from Unusual Location
slug: 2024-01-kernel-module-load
description: This rule detects the loading of a kernel module from an unusual location, which could indicate a rootkit attempting to maintain persistence on the system by hiding processes, files, or network activity.
date: "2024-01-03T16:25:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - defense-evasion
  - rootkit
  - linux
vendors:
  - Linux
products:
  - Linux Kernel
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1014
    technique_name: Rootkit
references:
  - https://decoded.avast.io/davidalvarez/linux-threat-hunting-syslogk-a-kernel-rootkit-found-under-development-in-the-wild/
  - https://attack.mitre.org/techniques/T1547/
  - https://attack.mitre.org/techniques/T1547/006/
  - https://attack.mitre.org/techniques/T1014/
rules:
  - title: Kernel Module Load from Unusual Location
    description: Detects the loading of kernel modules from unusual locations using insmod or modprobe.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1014
      - T1547.006
    data_sources:
      - process_creation
      - linux
  - title: Kernel Module Load from Unusual Location (Parent Process)
    description: Detects the loading of kernel modules when the parent process' working directory is an unusual location.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1014
      - T1547.006
    data_sources:
      - process_creation
      - linux
  - title: Kernel Module Load from Unusual Location (Command Line)
    description: Detects the loading of kernel modules with a command line argument pointing to an unusual location.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1014
      - T1547.006
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

This detection identifies the loading of Linux kernel modules from atypical directories, a technique used by attackers to execute code in kernel space for stealth and persistence.  After gaining initial access, adversaries may drop a malicious `.ko` file into a writable path like `/tmp` or `/dev/shm`. They then use `insmod` or `modprobe` to insert the module, potentially hiding processes, files, or network activity as part of a rootkit. This behavior is strongly related to the presence of rootkits, which are used to maintain a persistent and stealthy presence on a compromised system. Defenders should investigate any instance of a kernel module being loaded from an unexpected location, as it could indicate a severe compromise.

## Attack Chain

1.  Initial Access: The attacker gains initial access to the Linux system via an exploit or compromised credentials.
2.  Privilege Escalation: The attacker escalates privileges to root, enabling them to load kernel modules.
3.  Malicious Module Dropping: A malicious kernel module (`.ko` file) is dropped into a world-writable directory such as `/tmp` or `/dev/shm`.
4.  Module Loading: The attacker uses `insmod` or `modprobe` to load the malicious kernel module into the kernel.
5.  Rootkit Installation: The loaded module installs a rootkit, enabling the attacker to hide files, processes, and network connections.
6.  Persistence: The attacker establishes persistence by configuring the system to automatically load the malicious module on boot, potentially using systemd units, init scripts, or cron jobs.
7.  Defense Evasion: The rootkit hides its presence and activities from security tools and administrators.
8.  System Control: The attacker maintains full control over the compromised system, enabling them to execute arbitrary code, steal data, or launch further attacks.

## Impact

A successful attack can lead to complete compromise of the Linux system. A rootkit installed via a malicious kernel module can hide processes, files, and network activity, making detection difficult. The attacker can use the compromised system to steal sensitive data, launch attacks against other systems, or disrupt critical services. The scope of impact can range from a single compromised server to a widespread network breach, depending on the attacker's objectives.

## Recommendation

*   Deploy the Sigma rule "Kernel Module Load from Unusual Location" to your SIEM and tune for your environment to detect suspicious kernel module loading events.
*   Enable file integrity monitoring on world-writable directories like `/tmp` and `/dev/shm` to detect the creation of suspicious `.ko` files.
*   Harden systems by restricting module loading, enabling Secure Boot/module signature enforcement where supported, and limiting `CAP_SYS_MODULE` to trusted admins (reference: overview section).
*   Review recent kernel and audit telemetry (`dmesg`, `/var/log/kern.log`, `journalctl -k`, and any audit records) around the event time for insertion messages, signature/taint indicators, and any follow-on errors suggesting tampering.
*   Isolate affected hosts from the network and disable external access to prevent further module loads or lateral movement (reference: response and remediation section).
