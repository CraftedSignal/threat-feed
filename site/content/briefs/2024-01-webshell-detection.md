---
title: Web Shell Activity Detection via Process Monitoring
slug: 2024-01-webshell-detection
description: This brief focuses on detecting malicious activity related to web shells on Windows systems by identifying the execution of command interpreters and scripting engines as child processes of common web server processes, potentially indicating unauthorized command execution and persistent access.
date: "2024-01-09T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - webshell
  - persistence
  - initial-access
  - execution
  - windows
vendors:
  - Microsoft
  - Apache
  - NGINX
products:
  - Windows
  - IIS
  - Apache HTTP Server
  - NGINX
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.microsoft.com/security/blog/2020/02/04/ghost-in-the-shell-investigating-web-shell-attacks/
  - https://www.elastic.co/security-labs/elastic-response-to-the-the-spring4shell-vulnerability-cve-2022-22965
  - https://www.elastic.co/security-labs/hunting-for-persistence-using-elastic-security-part-1
rules:
  - title: 'Web Shell Detection: Script Process Child of Common Web Processes'
    description: Detects command interpreters (cmd.exe, powershell.exe) spawned by common web server processes (w3wp.exe, httpd.exe, nginx.exe), indicating potential web shell activity.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
      - persistence
    techniques:
      - T1059.001
      - T1059.003
      - T1190
      - T1505.003
    data_sources:
      - process_creation
      - windows
  - title: 'Web Shell Detection: PowerShell Execution from Web Server'
    description: Detects PowerShell execution as a child process of a web server, which is often indicative of web shell activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
      - persistence
    techniques:
      - T1059.001
      - T1190
      - T1505.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Web shells are malicious scripts placed on web servers to provide attackers with remote access and control. This threat brief addresses the detection of web shell activity on Windows servers, focusing on the execution of command interpreters and scripting engines (e.g., cmd.exe, powershell.exe, cscript.exe) as child processes of web server processes (e.g., w3wp.exe, httpd.exe, nginx.exe). The initial access vector is typically exploitation of a public-facing application. This activity allows threat actors to execute commands, upload/download files, and potentially pivot deeper into the network. The timeframe of interest is ongoing, as web shells remain a popular method for maintaining persistence in compromised environments. The scope of targeting is broad, as any vulnerable web server is susceptible to web shell placement and subsequent exploitation.

## Attack Chain

1.  **Initial Compromise:** A web server is compromised through the exploitation of a vulnerability in a public-facing web application (e.g., unpatched software, SQL injection).
2.  **Web Shell Upload:** The attacker uploads a malicious script (e.g., PHP, ASPX) to a publicly accessible directory on the web server.
3.  **Web Shell Execution:** The attacker accesses the web shell through a web browser, triggering its execution on the server.
4.  **Command Execution:** The web shell executes commands by spawning a command interpreter such as `cmd.exe` or `powershell.exe`.
5.  **Privilege Escalation:** The attacker attempts to elevate privileges using exploits or by leveraging misconfigurations.
6.  **Lateral Movement:** The attacker uses the compromised web server as a pivot point to access other systems on the network.
7.  **Data Exfiltration:** The attacker exfiltrates sensitive data from the compromised network.
8.  **Persistence:** The attacker establishes persistence by creating new user accounts or modifying existing ones, or by planting additional web shells.

## Impact

A successful web shell attack can result in complete compromise of the web server and potentially the entire network. This can lead to data breaches, financial losses, reputational damage, and disruption of services. The number of potential victims is large, as web servers are ubiquitous and often targeted by attackers. Specific sectors at risk include e-commerce, finance, healthcare, and government.

## Recommendation

*   Deploy the "Web Shell Detection: Script Process Child of Common Web Processes" Sigma rule to your SIEM and tune it for your environment to detect command execution via web shells.
*   Enable Sysmon process creation logging to capture process start events and command-line arguments, as required by the provided Sigma rules.
*   Implement a web application firewall (WAF) to prevent the initial exploitation of web application vulnerabilities.
*   Regularly scan web applications for vulnerabilities and apply patches promptly to prevent initial access.
*   Monitor network connections originating from web servers for suspicious outbound traffic, which may indicate command and control activity.
