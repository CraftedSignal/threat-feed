---
title: Laravel-Backup-Restore OS Command Injection (CVE-2026-53932)
slug: 2026-07-laravel-backup-restore-rce
description: A critical OS command injection vulnerability, tracked as CVE-2026-53932, exists in the wnx/laravel-backup-restore package (versions <= 1.9.3), allowing an attacker to execute arbitrary shell commands on the hosting system by crafting a malicious backup archive with shell metacharacters in a database dump filename, leading to application compromise, data tampering, and potential lateral movement.
date: "2026-07-09T21:12:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - os-command-injection
  - laravel
  - php
  - vulnerability
  - cve-2026-53932
vendors:
  - wnx
products:
  - laravel-backup-restore <= 1.9.3
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: shell metacharacters in the dump filename are interpreted by ... the platform shell on Windows.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: shell metacharacters in the dump filename are interpreted by `/bin/sh` on Unix-like systems
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-w9mx-xmg4-gc4r
rules:
  - title: Detect CVE-2026-53932 Exploitation - PHP Process Spawning Suspicious Commands (Windows)
    description: Detects exploitation of CVE-2026-53932 where the Laravel-Backup-Restore package's PHP process spawns suspicious shell commands or utilities on Windows due to OS command injection. This indicates arbitrary code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
      - impact
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
  - title: Detect CVE-2026-53932 Exploitation - PHP Process Spawning Suspicious Commands (Linux)
    description: Detects exploitation of CVE-2026-53932 where the Laravel-Backup-Restore package's PHP process spawns suspicious shell commands or utilities on Linux due to OS command injection. This indicates arbitrary code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
      - impact
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A significant OS command injection vulnerability, identified as CVE-2026-53932, affects the `wnx/laravel-backup-restore` package in versions prior to 1.9.4. This flaw allows an attacker to achieve arbitrary command execution on systems performing database restores. The vulnerability arises because the package improperly handles filenames within backup archives. When a specially crafted ZIP archive containing shell metacharacters in a database dump filename under the `db-dumps` directory is restored, the `laravel-backup-restore` package interpolates these unescaped filenames directly into database import commands. This execution occurs via Symfony's `Process::fromShellCommandline()`, which causes the shell metacharacters to be interpreted by `/bin/sh` on Unix-like systems or the platform shell on Windows. Successful exploitation can lead to full compromise of the application and the underlying server, operating with the privileges of the PHP/Laravel application user. This issue is not related to malicious SQL content but rather the structure of the backup archive's filenames.

## Attack Chain

1. An attacker crafts a malicious backup archive (e.g., a ZIP file) containing a `db-dumps` directory.
2. Inside the `db-dumps` directory, the attacker includes a database dump file with a filename that contains shell metacharacters (e.g., `dump.sql; cat /etc/passwd > /tmp/pwned.txt`).
3. The malicious backup archive is introduced to the target system, potentially through a compromised source, malicious upload, or direct access.
4. An operator or automated process on the target system initiates a database restore operation using the vulnerable `laravel-backup-restore` package.
5. During the restore, the package extracts the ZIP archive and identifies the database dump file within the `db-dumps` directory.
6. The `laravel-backup-restore` package constructs a shell command (e.g., `mysql ... < {dumpFile}`) for database import, interpolating the unescaped malicious filename directly into the command string.
7. The underlying Symfony `Process::fromShellCommandline()` executes the constructed command via `/bin/sh` or the platform shell, interpreting the shell metacharacters and executing the attacker's injected arbitrary commands (e.g., `cat /etc/passwd`).
8. The attacker's commands are executed on the server, leading to application compromise, data exfiltration, or further post-exploitation activities.

## Impact

Successful exploitation of CVE-2026-53932 allows an attacker to execute arbitrary shell commands as the PHP/Laravel application user on the system performing the database restore. This can lead to a severe compromise of the affected application and the underlying server. Consequences include unauthorized access to sensitive data, such as database credentials and application secrets, complete data tampering or destruction, and the installation of backdoors for persistent access. Depending on the permissions of the PHP user, attackers could achieve lateral movement within the network or elevate privileges, turning a simple restore operation into a full system compromise. The severity of the impact is high given the potential for complete control over the compromised server.

## Recommendation

* Immediately upgrade `wnx/laravel-backup-restore` to version 1.9.4 or higher to patch CVE-2026-53932.
* Deploy the Sigma rules titled "Detect CVE-2026-53932 Exploitation - PHP Process Spawning Suspicious Commands (Windows)" and "Detect CVE-2026-53932 Exploitation - PHP Process Spawning Suspicious Commands (Linux)" to your SIEM solution.
* Ensure process creation logging is enabled for `php` and its child processes on all Windows and Linux servers running Laravel applications.
* Review existing automated backup restore workflows and any manual restore procedures to minimize exposure to untrusted backup archives.
