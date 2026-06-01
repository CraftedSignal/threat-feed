---
title: Uncommon Destination Port Connection by Linux Web Server
slug: 2026-06-uncommon-web-server-port
description: This rule identifies unusual destination port network activity originating from a web server process on Linux systems, indicating potential web shell activity or unauthorized communication from a web server process to external systems by detecting egress connections from web server processes to non-standard ports while excluding common local IP ranges.
date: "2026-06-01T15:44:41Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - execution
  - command_and_control
  - web_shell
  - linux
vendors:
  - Elastic
products:
  - Elastic Defend
affected_os:
  - Linux
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
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1571
    technique_name: Non-Standard Port
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_web_server_sus_destination_port.toml
  - https://attack.mitre.org/techniques/T1505/
  - https://attack.mitre.org/techniques/T1505/003/
  - https://attack.mitre.org/tactics/TA0003/
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1059/004/
  - https://attack.mitre.org/tactics/TA0002/
  - https://attack.mitre.org/techniques/T1071/
  - https://attack.mitre.org/techniques/T1571/
  - https://attack.mitre.org/tactics/TA0011/
rules:
  - title: Uncommon Destination Port Connection by Linux Web Server
    description: Detects uncommon destination port connection by web server processes on Linux systems, excluding standard ports and local IP ranges.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
      - execution
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - network_connection
      - linux
  - title: Web Server Process Spawning Shell
    description: Detects web server processes spawning shell processes, potentially indicating web shell activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This detection rule identifies unusual outbound network connections initiated by web server processes on Linux systems. The rule is designed to detect potential web shell activity or unauthorized communication from a web server process to external systems. It works by monitoring egress connections from web server processes to non-standard ports, excluding common local IP ranges. This aims to highlight potential threats such as web shells or data exfiltration attempts originating from compromised web servers. The processes monitored include common web server applications like Apache, Nginx, and associated scripting environments. The rule focuses on identifying deviations from typical web server behavior to help defenders quickly identify potentially malicious activity.

## Attack Chain

1.  An attacker gains initial access to a Linux web server, potentially through exploiting a vulnerability in a web application.
2.  The attacker deploys a web shell (e.g., using PHP, Python, or Perl) to a publicly accessible directory on the web server.
3.  The attacker uses the web shell to execute commands on the server, often using a scripting interpreter like bash or sh.
4.  The web shell initiates a network connection to an external IP address on an uncommon destination port (i.e., not 80, 443, etc.).
5.  This outbound connection bypasses standard web server traffic and may be used for command and control or data exfiltration.
6.  The attacker may use this connection to download additional tools or exfiltrate sensitive data from the compromised server.
7.  The attacker may attempt to establish persistence by modifying web server configuration files or creating cron jobs.
8.  The ultimate objective is to maintain unauthorized access to the server and potentially pivot to other systems on the network or exfiltrate sensitive data.

## Impact

Compromised web servers can lead to significant data breaches, service disruptions, and reputational damage. If an attacker successfully deploys a web shell and initiates unauthorized outbound connections, they can exfiltrate sensitive data, install malware, or use the compromised server as a staging point for further attacks. The impact can range from a minor inconvenience to a major security incident, depending on the sensitivity of the data stored on the server and the attacker's objectives.

## Recommendation

*   Deploy the Sigma rule "Uncommon Destination Port Connection by Linux Web Server" to your SIEM and tune for your environment.
*   Enable Elastic Defend integration to collect the necessary network event data.
*   Review and allowlist legitimate administrative tasks or maintenance scripts that may trigger alerts by connecting to non-standard ports as mentioned in the false positives.
*   Investigate alerts generated by this rule promptly by reviewing the process name, user, destination IP address, and destination port.
*   Implement network segmentation to limit the web server's access to critical systems and data.
