---
title: Unusual Command Execution from Web Server Parent Process on Linux
slug: 2026-06-web-server-command-execution
description: This rule detects potential command execution from a web server parent process on a Linux host, indicating a possible web shell attack where adversaries exploit web server vulnerabilities to execute arbitrary commands.
date: "2026-06-01T15:44:23Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - web-shell
  - command-execution
  - persistence
  - linux
vendors:
  - Elastic
  - Apache
  - Nginx
products:
  - Elastic Defend
  - Apache
  - Nginx
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_web_server_sus_command_execution.toml
  - https://attack.mitre.org/techniques/T1505/
  - https://attack.mitre.org/techniques/T1505/003/
  - https://attack.mitre.org/tactics/TA0003/
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1059/004/
  - https://attack.mitre.org/tactics/TA0002/
  - https://attack.mitre.org/techniques/T1071/
  - https://attack.mitre.org/tactics/TA0011/
rules:
  - title: Detect Unusual Shell Spawned by Web Server
    description: Detects shell processes (bash, sh, etc.) spawned by common web server processes (apache, nginx, etc.) indicating potential web shell activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.004
      - T1505.003
    data_sources:
      - process_creation
      - linux
  - title: Detect Web Server Child Process Executing Shell with Command Line Arguments
    description: Detects shell processes spawned by web servers executing commands with the -c flag.
    platform: sigma
    severity: low
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.004
      - T1505.003
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This detection rule identifies unusual command execution originating from web server parent processes on Linux hosts, a common tactic used in web shell attacks. Adversaries exploit vulnerabilities in web servers such as Apache and Nginx to execute arbitrary commands, blending malicious activity with legitimate server processes. The rule focuses on identifying unusual patterns and contexts, such as unexpected working directories or command structures, to flag potential compromises. This technique allows attackers to maintain persistence, execute commands, and potentially establish command and control within the compromised system. The rule is designed to detect such activities by monitoring process execution events and comparing them against a baseline of normal web server behavior.

## Attack Chain

1.  An attacker exploits a vulnerability in a web application running on a Linux server.
2.  The attacker gains initial access and uploads a web shell, a malicious script (e.g., PHP, Python) that allows remote command execution.
3.  The web server (e.g., Apache, Nginx) spawns a process to execute the web shell.
4.  The attacker uses the web shell to execute commands, such as spawning a reverse shell or listing files.
5.  A shell process (e.g., bash, sh) is created as a child of the web server process.
6.  The attacker uses the shell to perform reconnaissance, such as identifying user accounts and network configurations.
7.  The attacker attempts to establish persistence by creating a cron job or modifying system files.
8.  The attacker uses the compromised server as a command and control node to communicate with other systems or exfiltrate data.

## Impact

A successful web shell attack can lead to complete compromise of the web server and potentially other systems on the network. Attackers can steal sensitive data, modify web pages, or use the server to launch further attacks. The impact can range from data breaches and defacement to denial-of-service attacks and lateral movement within the network. While this specific detection rule has low severity, failing to detect and remediate these attacks can have significant consequences.

## Recommendation

*   Deploy the Sigma rule `Detect Unusual Shell Spawned by Web Server` to your SIEM and tune for your environment to identify suspicious command execution from web server processes.
*   Investigate alerts triggered by the `Detect Web Server Child Process Executing Shell with Command Line Arguments` Sigma rule to identify potentially compromised web servers.
*   Review the process command lines from the alerts and exclude specific working directories like /var/www/dev or /var/www/test from the rule to reduce false positives.
*   Implement additional monitoring and alerting for similar activities, focusing on unusual command executions and web server behavior as mentioned in the `Response and Remediation` section of the rule documentation.
