---
title: Suspicious Command Execution via Web Server on Linux
slug: 2026-06-suspicious-webserver-command-execution
description: Identifies suspicious command executions via a web server on Linux systems, potentially indicating a vulnerability exploitation or remote shell access for persistence.
date: "2026-06-01T15:45:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - endpoint
  - linux
  - persistence
  - initial-access
  - vulnerability
vendors:
  - Elastic
  - nginx
  - Apache
  - caddy
  - mongrel_rails
  - uwsgi
  - daphne
  - flask
  - zabbix
  - Asterisk
  - varnish
  - uvicorn
  - waitress
  - Starman
  - frankenphp
products:
  - Elastic Defend
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1059.004
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_webserver_suspicious_command_execution.toml
rules:
  - title: Detect Suspicious Command Execution via Web Server - Reverse Shell
    description: Detects command execution via web server with reverse shell patterns
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Command Execution via Web Server - File Access
    description: Detects command execution via web server accessing sensitive files
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - initial_access
      - persistence
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Command Execution via Web Server - Cloud Credentials
    description: Detects command execution via web server accessing cloud credentials files or environment variables.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1059.004
      - T1552
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

This detection rule identifies suspicious command executions initiated by web servers on Linux systems. Attackers may exploit web application vulnerabilities to execute arbitrary commands, gaining remote shell access and establishing persistence. The rule focuses on detecting shell commands with suspicious patterns, often indicative of vulnerability exploitation or malicious activity, such as reverse shells, file access to sensitive configuration files, and attempts to download or execute malicious payloads. The rule relies on process execution data collected by Elastic Defend. While network monitoring tools can exhibit similar behaviors, defenders should investigate any matched events to determine maliciousness.

## Attack Chain

1.  The attacker identifies a vulnerable web application running on a Linux server.
2.  The attacker exploits a vulnerability (e.g., command injection, file upload) in the web application.
3.  The web server (e.g., Apache, Nginx) executes a shell command (e.g., bash, sh) to facilitate the exploit.
4.  The shell command includes suspicious patterns, such as reverse shell attempts (e.g., `/dev/tcp`, `nc`), file access to sensitive system files (e.g., `/etc/passwd`, `/etc/shadow`), or attempts to download remote payloads (e.g., `curl`, `wget`).
5.  The attacker gains initial access to the system through the executed command or reverse shell.
6.  The attacker attempts to establish persistence by modifying cron jobs or SSH configurations.
7.  The attacker performs further reconnaissance and lateral movement within the compromised network.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data, modification of system configurations, installation of malware, and further compromise of the network. This can result in data breaches, system downtime, and reputational damage. Given the wide variety of web server platforms and web application technologies, the potential victim pool is vast.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM and tune for your environment, focusing on reducing false positives by allowlisting legitimate processes and commands.
*   Ensure that Elastic Defend is properly configured on all Linux endpoints to collect process execution data as required by the provided Sigma rules.
*   Investigate any alerts triggered by the Sigma rules, focusing on the command line arguments and the parent process to determine the legitimacy of the activity.
*   Review and harden web application configurations to prevent command injection and file upload vulnerabilities.
*   Implement strong input validation and output encoding mechanisms to mitigate web application vulnerabilities.
