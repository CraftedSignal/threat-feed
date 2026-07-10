---
title: Glances Command Injection Vulnerability via Dynamic Configuration
slug: 2024-01-glances-command-injection
description: Glances versions 4.5.2 and earlier are vulnerable to command injection via dynamic configuration values, allowing arbitrary command execution with the privileges of the Glances process if an attacker can modify or influence configuration files, potentially leading to privilege escalation.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - glances
  - command-injection
  - privilege-escalation
  - cve-2026-33641
vendors:
  - Glances
products:
  - Glances
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-qhj7-v7h7-q4c7
rules:
  - title: Detect Glances Configuration Command Injection
    description: Detects command injection attempts in Glances configuration files by monitoring process creation events where the command line contains a backtick.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
  - title: Detect Glances Configuration File Modification
    description: Detects modification of Glances configuration files by monitoring file creation or modification events.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Glances, a system monitoring tool, contains a command injection vulnerability in versions 4.5.2 and earlier. The vulnerability stems from the dynamic configuration parsing in `Config.get_value()`, where substrings enclosed in backticks are interpreted and executed as system commands. This behavior occurs without proper validation or restriction, allowing an attacker to inject arbitrary commands. If an attacker can modify or influence the Glances configuration files, these commands will execute automatically with the privileges of the Glances process. This is particularly concerning in deployments where Glances runs with elevated privileges, such as when it is configured as a system service. The vulnerability is tracked as CVE-2026-33641.

## Attack Chain

1.  Attacker gains access to the Glances configuration file (e.g., through misconfigured file permissions, shared writable directories, or compromised configuration management systems).
2.  Attacker modifies the configuration file to include a malicious command within backticks in a configuration value (e.g., `url_prefix = 'id'`).
3.  Glances is started or the configuration is reloaded.
4.  During configuration parsing, the `Config.get_value()` function in `glances/config.py` identifies the backtick-enclosed substring.
5.  The identified command is extracted and passed to the `system_exec()` function in `glances/globals.py`.
6.  `system_exec()` executes the command using `subprocess.run()` effectively running the injected code on the host.
7.  The output of the executed command replaces the original configuration value.
8.  The attacker achieves arbitrary command execution with the privileges of the Glances process, potentially leading to privilege escalation if Glances runs with elevated permissions.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the system with the privileges of the Glances process. If Glances is running as root or another privileged user, this can lead to full system compromise and privilege escalation. The vulnerability affects any system where Glances versions 4.5.2 or earlier is installed and the configuration file is modifiable by a malicious actor. Scenarios include misconfigured file permissions allowing unauthorized config modification, shared systems where configuration directories are writable by multiple users, container environments with mounted configuration volumes, and automated configuration management systems that ingest untrusted data.

## Recommendation

*   Upgrade Glances to a version greater than 4.5.2 to patch CVE-2026-33641.
*   Implement strict file permission controls on Glances configuration files to prevent unauthorized modification (reference Attack Chain step 1).
*   Deploy the Sigma rule `Detect Glances Configuration Command Injection` to detect attempts to exploit this vulnerability by monitoring process creation events after config file modification.
*   Monitor file integrity of Glances configuration files using a file integrity monitoring (FIM) system and alert on unauthorized changes to configuration files (reference Attack Chain step 2).
