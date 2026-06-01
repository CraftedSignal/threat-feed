---
title: Suspicious Web Server Child Process Execution via Elastic Defend for Containers
slug: 2026-06-suspicious-webserver-child-process
description: This rule detects the exploitation of a web server through the execution of a suspicious process by common web server user accounts within a containerized environment, potentially indicating the uploading of a web shell to maintain system access, and covers persistence, execution, and command and control tactics.
date: "2026-06-01T15:48:08Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - 'Data Source: Elastic Defend for Containers'
  - 'Domain: Container'
  - 'OS: Linux'
  - 'Use Case: Threat Detection'
  - 'Tactic: Persistence'
  - 'Tactic: Execution'
  - 'Tactic: Command and Control'
  - 'Resources: Investigation Guide'
vendors:
  - Elastic
products:
  - Elastic Defend for Containers
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/persistence_suspicious_webserver_child_process_execution.toml
rules:
  - title: Detect Web Server Suspicious Child Processes - Shell Spawn
    description: Detects web server processes spawning shell processes with suspicious arguments indicative of command execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Web Server Suspicious Child Processes - Reverse Shell
    description: Detects web server processes spawning shell processes with reverse shell arguments.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.004
      - T1071.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This detection rule, sourced from Elastic's detection rules repository and designed for use with Elastic Defend for Containers, identifies potential web server exploitation attempts. The rule focuses on detecting suspicious processes spawned by web server user accounts within containers. This can be indicative of attackers uploading web shells or exploiting remote command execution vulnerabilities to maintain access. The rule specifically looks for parent processes like nginx, apache2, or php-fpm executing shell commands with suspicious arguments. The rule was initially created on 2026/02/06 and updated on 2026/06/01, with a minimum stack version of 9.3.0, when Defend for Containers integration was reintroduced. It is important for defenders to monitor such activity as it can lead to persistence, lateral movement, and further compromise within the containerized environment.

## Attack Chain

1. Initial Access: Attacker gains initial access to the web server, potentially through a vulnerability such as remote code execution (RCE) or by exploiting weak credentials.
2. Web Shell Upload: The attacker uploads a web shell (e.g., PHP shell) to a publicly accessible directory on the web server.
3. Command Execution: The attacker uses the web shell to execute commands on the server, often using a web-service account.
4. Suspicious Process Spawn: The web server process spawns a shell process (e.g., bash, sh) with suspicious arguments, such as those used for reverse shells, file manipulation, or credential access.
5. Persistence: The attacker establishes persistence by creating cron jobs or modifying system files.
6. Lateral Movement: The attacker uses the compromised server as a pivot point to move laterally within the network, potentially targeting other containers or hosts.
7. Command and Control: The attacker establishes a command and control (C2) channel with an external server to remotely control the compromised system.
8. Data Exfiltration/System Damage: The attacker exfiltrates sensitive data or causes damage to the system, depending on their objectives.

## Impact

Successful exploitation of web servers can lead to a range of negative consequences, including data breaches, system compromise, and financial losses. Attackers can use compromised web servers to steal sensitive data, launch attacks on other systems, or disrupt business operations. The potential impact is significant, particularly for organizations that rely on web applications to conduct business. The severity is rated high due to the potential for significant damage and the relative ease with which such attacks can be carried out.

## Recommendation

*   Deploy the "Web Server Exploitation Detected via Defend for Containers" EQL rule to your Elastic Stack instance to detect suspicious process execution by web servers.
*   Enable Elastic Defend for Containers with a minimum stack version of 9.3.0 to collect the necessary data for the rule to function.
*   Prioritize investigation of alerts generated by the rule with a risk score of 73, particularly those involving reverse shells, file access, or credential access, as indicated in the rule's `query`.
*   Review and tune the rule's `query` to reduce false positives based on your specific environment and application configurations, as described in the "False positive analysis" section of the rule's `note`.
*   Implement network segmentation and egress filtering to limit the potential impact of compromised containers, as suggested in the "Response and remediation" section of the rule's `note`.
