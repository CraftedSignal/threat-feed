---
title: Anyquery Arbitrary File Write (AFW) Leads to Remote Code Execution (RCE)
slug: 2026-07-anyquery-afw-rce
description: Anyquery in server mode is vulnerable to arbitrary file write (AFW) due to its failure to restrict native SQLite disk manipulation commands like `ATTACH DATABASE`. Unauthenticated attackers can connect to the MySQL-compatible server port and write arbitrary files (e.g., PHP webshells, malicious cronjobs) to any path writable by the Anyquery process, which can lead to remote code execution (RCE) with the privileges of the Anyquery process, significantly impacting system integrity and availability.
date: "2026-07-14T19:16:28Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - arbitrary-file-write
  - rce
  - anyquery
  - sqlite
  - server-mode
  - vulnerability
vendors:
  - julien040
products:
  - Anyquery ( < 0.4.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers connecting to the MySQL-compatible server port
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: executing the reverse shell payload with root privileges
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: ""
    evidence: dropping a PHP web shell if a web server is running
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: ""
    evidence: overwriting system cronjobs
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-xrcf-6jh3-ggvx
rules:
  - title: Detects CVE-2026-50006 Exploitation - Anyquery AFW to Cron Directory
    description: Detects the creation of suspicious files by the 'anyquery' process in critical cronjob directories, indicating potential Arbitrary File Write leading to RCE (CVE-2026-50006).
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053.003
      - T1505.003
    data_sources:
      - file_event
      - linux
  - title: Detects CVE-2026-50006 Exploitation - Anyquery AFW to Web Root
    description: Detects the creation of suspicious files by the 'anyquery' process in web server root directories, indicating potential Arbitrary File Write leading to RCE (CVE-2026-50006) via web shell.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
  - title: Detects CVE-2026-50006 Exploitation - Anyquery Server Listening Broadly
    description: Detects the 'anyquery server' process being launched with an insecure broad network listening host (0.0.0.0), a prerequisite for CVE-2026-50006 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

A critical vulnerability (CVE-2026-50006) has been identified in Anyquery versions prior to 0.4.5, specifically when the application is operating in `server` mode. Unauthenticated attackers can leverage this flaw by connecting to the exposed MySQL-compatible server port. The vulnerability stems from Anyquery's failure to restrict SQLite's `ATTACH DATABASE` command, allowing adversaries to write arbitrary files to the underlying filesystem. This Arbitrary File Write (AFW) can be exploited to achieve Remote Code Execution (RCE) by dropping malicious files such as PHP web shells into web server directories or injecting cronjob entries into system directories like `/etc/cron.d`. This means an attacker can gain control over the affected system with the privileges of the running Anyquery process, posing a severe threat to data integrity and system availability.

## Attack Chain

1. An unauthenticated attacker connects to the exposed Anyquery MySQL-compatible server port (e.g., 8070).
2. The attacker executes an `ATTACH DATABASE` SQL command to specify a new SQLite database file and a sensitive target path on the victim's filesystem (e.g., `/etc/cron.d/pwn` or `/var/www/html/shell.php`).
3. The attacker creates a table within the newly attached database using `CREATE TABLE`.
4. The attacker injects a malicious payload (e.g., a reverse shell command for a cronjob, or PHP `system()` function for a web shell) into the table using an `INSERT INTO` SQL command.
5. Anyquery writes the SQLite database file containing the malicious payload to the specified sensitive path.
6. A system service (e.g., cron daemon, web server) attempts to process the newly created file, ignoring the SQLite binary header and parsing the valid injected malicious code.
7. The malicious code (e.g., reverse shell, web shell commands) is executed with the privileges of the Anyquery process, leading to Remote Code Execution.

## Impact

This vulnerability carries a CVSS score of 9.1 (Critical), indicating high severity. If exploited, the integrity of the affected system is severely compromised as arbitrary files can be written or overwritten, potentially corrupting critical system data. Availability is also highly impacted, as overwriting essential system files or configurations can lead to a complete Denial of Service (DoS). When Anyquery runs with elevated privileges (e.g., as root) or can write to critical directories like web roots or cronjob folders, the AFW escalates directly to Remote Code Execution (RCE) with a CVSS score of 9.8 (Critical), allowing full system compromise, persistence, and potential privilege escalation.

## Recommendation

* Patch CVE-2026-50006 by upgrading Anyquery to version 0.4.5 or later immediately.
* Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious file creations by the `anyquery` process.
* Enable `file_event` logging for Linux endpoints to capture file creations in sensitive directories like `/etc/cron.d/` and `/var/www/html/`.
* Enable `process_creation` logging to monitor for suspicious `anyquery` process command-line arguments, especially `--host 0.0.0.0`.
