---
title: Detect Linux Kernel Module Load via Built-in Utility
slug: 2026-07-linux-kernel-module-load-insmod
description: This threat involves adversaries with root privileges using the `insmod` or `modprobe` utilities to load malicious Linux kernel object files (.ko), often rootkits, which provides complete system control and evasion capabilities, making detection of this uncommon activity critical.
date: "2026-07-16T21:30:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - linux
  - persistence
  - defense-evasion
  - rootkit
  - endpoint-security
  - threat-detection
  - elastic-defend
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Threat actors can use this binary, given they have root privileges, to load a rootkit on a system providing them with complete control and the ability to hide from security products.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Threat actors can use this binary, given they have root privileges, to load a rootkit on a system providing them with complete control and the ability to hide from security products.
    confidence_band: high
references:
  - https://decoded.avast.io/davidalvarez/linux-threat-hunting-syslogk-a-kernel-rootkit-found-under-development-in-the-wild/
rules:
  - title: Detect Linux Kernel Module Load via Built-in Utility
    description: Detects the use of `insmod`, `modprobe`, or `kmod` to load Linux kernel object files, indicating potential rootkit deployment or malicious activity.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1547.006
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

Threat actors with root privileges on a Linux system can load malicious kernel object files (rootkits) using the `insmod` or `modprobe` utilities. This technique, updated in a detection rule on July 16, 2026, and supported by Elastic Stack version 9.3.0 and newer, allows adversaries to gain complete control over a compromised system and effectively hide their presence from security products. This activity, which is highly unusual in legitimate environments, serves as a significant indicator of compromise for persistence and defense evasion. The primary motivation for attackers employing this method is to establish covert and enduring access, enabling various post-exploitation activities without detection.

## Attack Chain

1. Adversary gains initial access to a Linux system, likely through a vulnerability exploit, stolen credentials, or social engineering.
2. The attacker elevates their privileges to root on the compromised system, a prerequisite for loading kernel modules.
3. A malicious Linux kernel object (.ko) file, often a rootkit, is staged onto the system.
4. The attacker executes the `insmod` or `modprobe` utility to load the staged malicious kernel module into the operating system.
5. The loaded kernel module activates, establishing deep system control and mechanisms for hiding its presence.
6. The rootkit modifies system behavior or hides malicious processes/files, granting persistent access and evading security products.
7. With complete control and stealth, the attacker conducts further malicious activities, such as data exfiltration or deploying additional malware.

## Impact

Successful exploitation allows attackers to gain complete control over the compromised Linux system, granting them the ability to evade security products and maintain persistent access. This can lead to severe consequences, including unauthorized data exfiltration, system integrity compromise, the deployment of additional malware, and the use of the compromised host for further attacks. Specific victim counts or targeted sectors are not detailed, but any Linux-based system with root privileges could be susceptible to this technique.

## Recommendation

* Deploy the Sigma rule "Detect Linux Kernel Module Load via Built-in Utility" to your SIEM environment to detect suspicious kernel module loading activities.
* Enable `process_creation` logging for your Linux endpoints, specifically ensuring Elastic Defend is configured to collect such events for the rule above.
* Investigate the kernel object file ($osquery_1) that was loaded for signs of malicious intent.
* Investigate the script execution chain (parent process tree) ($osquery_2) for unknown processes or unusual binaries leading to module loading.
* Examine network connections, listening ports ($osquery_3), and open sockets ($osquery_4) for abnormal behaviors by the process or user involved in kernel module loading.
* Implement host-based intrusion detection systems (HIDS) or endpoint detection and response (EDR) solutions that can monitor kernel-level activities and command execution.
