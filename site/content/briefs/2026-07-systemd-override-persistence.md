---
title: Systemd Service Override Configuration File Creation for Persistence
slug: 2026-07-systemd-override-persistence
description: Attackers can leverage the creation or renaming of Systemd override configuration files in standard or user service directories to achieve persistence or privilege escalation on Linux systems, altering service behavior to execute malicious commands during system startup or at predefined intervals via timers, thereby maintaining unauthorized access or evading detection.
date: "2026-07-03T16:13:32Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - linux
  - endpoint
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: Malicious actors can leverage systemd override configuration files to achieve persistence by creating or modifying services to execute malicious commands or payloads during system startup or at a predefined interval by adding a systemd timer.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: Malicious actors can leverage systemd override configuration files to achieve ... privilege escalation by creating or modifying services to execute malicious commands or payloads during system startup or at a predefined interval by adding a systemd timer.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_systemd_override_conf_creation.toml
rules:
  - title: Detect Systemd Service Override Configuration File Creation
    description: Detects the creation or renaming of Systemd override configuration files, which can be leveraged by attackers for persistence or privilege escalation on Linux systems.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1543
      - T1543
      - T1543.002
      - T1543.002
    data_sources:
      - file_event
      - linux
rules_count: 1
---

Malicious actors can exploit Systemd override configuration files to establish persistence or escalate privileges on Linux systems. These files, such as `override.conf`, allow for modification of Systemd service behavior without altering the original service unit file. By crafting and placing these override files in specific system or user service directories (e.g., `/etc/systemd/system/<service>.d/` or `~/.config/systemd/user/<service>.d/`), attackers can introduce malicious commands to execute during system startup, service restarts, or at scheduled times via Systemd timers. This technique enables them to maintain unauthorized access, execute additional payloads, or evade detection, as the changes can survive reboots and often go unnoticed by standard configuration checks. The technique targets the core Systemd service management framework common across modern Linux distributions.

## Attack Chain

1.  An attacker gains initial access to a Linux system, potentially through compromised credentials, exploited vulnerabilities, or other means.
2.  The attacker identifies a target Systemd service whose behavior they wish to alter for persistence (e.g., `sshd.service`, a web server daemon, or a custom application).
3.  A malicious Systemd override configuration file (e.g., `override.conf`) is crafted, containing directives such as `ExecStartPre`, `ExecStartPost`, `Environment`, or `OnCalendar` to execute arbitrary commands.
4.  The attacker writes or renames this malicious `.conf` file into a Systemd override directory for the target service, such as `/etc/systemd/system/<service>.d/` for system-wide services or `~/.config/systemd/user/<service>.d/` for user-specific services.
5.  To activate the changes immediately, the attacker may force Systemd to reload its configuration using `systemctl daemon-reload` and potentially restart the affected service.
6.  Upon the next service start, user login, or system reboot, the malicious commands specified in the override file are executed, providing the attacker with persistent access or other intended malicious capabilities.

## Impact

The successful exploitation of Systemd override configuration files can lead to sustained unauthorized access, arbitrary code execution with elevated privileges, and the compromise of system integrity. Attackers can embed backdoors that survive reboots, launch additional malware, or exfiltrate sensitive data. If critical system services like `sshd` or security agents are targeted, the impact can be severe, potentially leading to full system control or a complete bypass of security monitoring. The persistence mechanism is stealthy, making detection and remediation challenging without specific monitoring.

## Recommendation

*   Deploy the Sigma rule "Detect Systemd Service Override Configuration File Creation" to your SIEM to alert on suspicious `.conf` file creation or renaming in Systemd override directories.
*   Ensure that file integrity monitoring (FIM) is enabled for Systemd service directories, specifically watching for changes to `*.service.d/override.conf` files, to complement the rule above.
*   Review any triggered alerts by opening the detected override file and comparing it against approved baselines and recent change requests, focusing on `ExecStart`, `ExecStartPre`, `ExecStartPost`, `Environment`, and `OnCalendar` directives.
*   Trace the process responsible for creating or renaming the `.conf` file back to its origin (parent process, user, and execution context) to determine legitimacy.
*   Isolate affected Linux hosts from the network, preserve the malicious `override.conf` file and associated artifacts, and remove the persistence by deleting the drop-in directory or `override.conf` after forensic collection.
