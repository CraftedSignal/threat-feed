---
title: Linuxfabrik Monitoring Plugins Local Privilege Escalation (CVE-2026-55426)
slug: 2026-07-linuxfabrik-lpe
description: A local privilege escalation vulnerability (CVE-2026-55426) in Linuxfabrik Monitoring Plugins, specifically affecting the `restic-check` plugin and others, allows an attacker controlling the 'nagios' user to inject arbitrary commands via arguments like `--repo`, which are then executed with root privileges due to the plugin's use of `shell_exec` and common sudoer configurations.
date: "2026-07-06T21:15:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - command-injection
  - linux
  - monitoring
vendors:
  - Linuxfabrik
products:
  - Linuxfabrik Monitoring Plugins
  - linuxfabrik-lib
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: When a check plugin places user provided input inside a command which is passed to `shell_exec`, an attacker can abuse this to run arbitrary commands... The full restic command is assembled... before it is passed to `shell_exec`. `shell_exec` then splits the command up in three parts at the | boundaries and executes the parts separately, which also executes the embedded command.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: This is mainly dangerous for plugins which are listed in the sudoers file, because this allows an attacker controlling the nagios user to get root privileges.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-798h-hpph-m24j
rules:
  - title: Detects CVE-2026-55426 Exploitation - Linuxfabrik Plugin Shell Injection
    description: Detects CVE-2026-55426 exploitation - execution of Linuxfabrik Monitoring Plugins (e.g., restic-check) via sudo by the 'nagios' user with shell metacharacters in arguments, indicating command injection.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1059
      - T1059.004
      - T1548
      - T1548.001
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

A critical local privilege escalation vulnerability, CVE-2026-55426, has been identified in Linuxfabrik Monitoring Plugins. This flaw, present in versions of `linuxfabrik-lib` prior to 5.0.0 and Linuxfabrik Monitoring Plugins before v5.2.0, arises when a plugin like `restic-check` uses `shell_exec` to process user-provided input within a command string. Attackers with control over the 'nagios' user can exploit this by injecting shell metacharacters, such as a pipe (`|`), into command-line arguments like `--repo`. Since these plugins are often configured to run with elevated privileges via `sudo`, successful exploitation grants the attacker arbitrary command execution as the root user. This vulnerability poses a significant risk to Linux systems utilizing these monitoring plugins, enabling an attacker to fully compromise the host.

## Attack Chain

1.  An attacker gains initial access to a Linux system, obtaining privileges as a low-privileged user, such as the `nagios` user.
2.  The attacker identifies that Linuxfabrik Monitoring Plugins, specifically a vulnerable plugin like `restic-check`, is installed and configured to run with elevated privileges (e.g., via `sudo`) by the `nagios` user.
3.  The attacker crafts a malicious input string containing shell metacharacters (e.g., `|touch /root/nagios-was-here|`) to inject into a plugin argument, such as the `--repo` argument for `restic-check`.
4.  The `nagios` user executes the vulnerable plugin via `sudo`, passing the crafted malicious input as an argument (e.g., `sudo /usr/lib64/nagios/plugins/restic-check --repo '|touch /root/nagios-was-here|'`).
5.  The vulnerable plugin concatenates the malicious input directly into a command string without proper sanitization or escaping.
6.  The unsanitized command string is passed to `shell_exec`, which interprets the shell metacharacters.
7.  `shell_exec` splits the command string at the `|` boundaries and executes the injected arbitrary command (e.g., `touch /root/nagios-was-here`) in addition to the legitimate plugin commands.
8.  The injected command runs with the elevated privileges of the plugin process (typically `root`), resulting in local privilege escalation and arbitrary command execution.

## Impact

The primary impact of CVE-2026-55426 is a local privilege escalation, allowing an attacker to escalate privileges from a compromised `nagios` user (or other user configured to run these plugins via `sudo`) to `root`. Successful exploitation results in arbitrary command execution as `root` on the affected Linux system. This grants the attacker full control over the compromised server, enabling them to install backdoors, exfiltrate sensitive data, disrupt services, or use the system as a pivot point for further attacks within the network. This vulnerability affects any organization using Linuxfabrik Monitoring Plugins on their Linux infrastructure.

## Recommendation

*   **Patch CVE-2026-55426 immediately** by updating `linuxfabrik-lib` to version 5.0.0 or higher.
*   **Update Linuxfabrik Monitoring Plugins** to a version equal to or greater than v5.2.0, which incorporates the patched `linuxfabrik-lib`.
*   **Deploy the Sigma rule** provided in this brief to your SIEM for detecting attempts to exploit CVE-2026-55426.
*   **Enable logging for process creation and command-line arguments** on your Linux systems to capture activity related to monitoring plugins, which is critical for the provided Sigma rule.
