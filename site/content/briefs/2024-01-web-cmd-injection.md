---
title: Web Server Potential Command Injection Request
slug: 2024-01-web-cmd-injection
description: The rule detects potential command injection attempts via web server requests by identifying URLs that contain suspicious patterns commonly associated with command execution payloads.
date: "2024-01-03T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - web-server
  - command-injection
  - persistence
vendors:
  - Nginx
  - Apache
  - Microsoft
  - Traefik
products:
  - Nginx
  - Apache HTTP Server
  - Apache Tomcat
  - IIS
  - Traefik
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Reconnaissance
    technique_id: T1595
    technique_name: Active Scanning
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://attack.mitre.org/techniques/T1505/
  - https://attack.mitre.org/techniques/T1505/003/
rules:
  - title: Web Server Potential Command Injection - Process
    description: Detects suspicious process creation related to web server command injection attempts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - process_creation
      - linux
  - title: Web Server Potential Command Injection - Network
    description: Detects suspicious network connections originating from web server processes indicative of reverse shells or command execution.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1505.003
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

This rule aims to detect potential command injection attempts via web server requests by identifying URLs that contain suspicious patterns associated with command execution payloads. Attackers exploit vulnerabilities in web applications to inject and execute arbitrary commands on the server, often using interpreters like Python, Perl, Ruby, PHP, or shell commands. The rule focuses on low-volume requests with HTTP 200 status codes. This activity matters because attackers use successful requests to trigger server-side command injection and gain persistence or control without obvious errors. It covers a wide range of web servers, including Nginx, Apache, Apache Tomcat, IIS, and Traefik.

## Attack Chain

1. An attacker identifies a vulnerable web application endpoint.
2. The attacker crafts a malicious HTTP request containing a command injection payload within the URL parameters, targeting known vulnerabilities.
3. The vulnerable web server processes the request, passing the malicious payload to the underlying system.
4. The payload includes interpreter flags (e.g., `python -c`, `bash -c`), shell invocations, or netcat commands designed for reverse shell creation.
5. The injected command executes on the server, potentially downloading a malicious script or establishing a reverse shell connection.
6. The attacker leverages the reverse shell for further reconnaissance, lateral movement, or privilege escalation within the compromised environment.
7. The attacker modifies system configurations, such as cron jobs or SSH keys, to establish persistence.
8. The attacker gains control of the server, allowing them to exfiltrate sensitive data or deploy further malicious payloads.

## Impact

Successful command injection can lead to complete compromise of the web server and potentially the entire network. While this detection focuses on low-volume 200 status code responses, a successful attack can allow the attacker to gain a persistent foothold, steal sensitive data, or use the compromised server as a launchpad for further attacks. The severity of the impact depends on the privileges of the web server process and the sensitivity of the data stored on the server or accessible from it.

## Recommendation

*   Deploy the Sigma rule `Web Server Potential Command Injection - Process` to your SIEM and tune for your environment.
*   Deploy the Sigma rule `Web Server Potential Command Injection - Network` to your SIEM and tune for your environment.
*   Block the offending source IPs and User-Agents at the WAF/reverse proxy if identified.
