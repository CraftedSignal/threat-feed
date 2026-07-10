---
title: Web Server Request Command Injection Attempt
slug: 2024-01-web-server-cmd-injection
description: Detection of potential command injection attempts via web server requests by identifying URLs containing suspicious patterns associated with command execution payloads, which attackers exploit to execute arbitrary commands on the server.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-injection
  - web-server
  - persistence
vendors:
  - Apache
  - Microsoft
  - Nginx
  - Traefik
products:
  - Apache
  - Apache Tomcat
  - IIS
  - Nginx
  - Traefik
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
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
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/persistence_web_server_potential_command_injection.toml
  - https://attack.mitre.org/techniques/T1505/
  - https://attack.mitre.org/techniques/T1505/003/
rules:
  - title: Detect Web Server Request Containing Command Injection Keywords
    description: Detects web server requests that contain keywords commonly associated with command injection attempts, such as shell interpreters, netcat, or file read attempts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - nginx|apache|apache_tomcat|iis|traefik
  - title: Detect Web Server Request with Base64 Encoded Command
    description: Detects web server requests that contain base64 encoded commands, often used to obfuscate malicious payloads.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - nginx|apache|apache_tomcat|iis|traefik
rules_count: 2
---

This detection identifies potential command injection attempts targeting web servers. Attackers exploit vulnerabilities in web applications to inject and execute arbitrary commands on the server. This is achieved by crafting malicious URLs that include suspicious patterns commonly associated with command execution, such as interpreter invocations (Python, Perl, Ruby, PHP), shell commands, and other techniques to gain unauthorized access and control. The detection logic focuses on identifying HTTP requests with a status code of 200 (OK) to filter out noisy logs that may not represent successful command execution attempts. This proactive monitoring helps security teams to promptly identify and respond to potential threats before significant damage can occur. The rule logic covers Nginx, Apache, Apache Tomcat, IIS, and Traefik access logs.

## Attack Chain

1.  The attacker identifies a vulnerable web application endpoint that is susceptible to command injection.
2.  The attacker crafts a malicious HTTP GET or POST request containing a command injection payload within the URL or request parameters. This payload might include shell metacharacters, encoded commands, or references to interpreters like Python, Perl, or Bash.
3.  The web server receives the malicious request and processes it. Due to the vulnerability, the injected command is executed by the server's operating system.
4.  The attacker leverages the command execution to perform reconnaissance, such as listing directories, reading files, or identifying system information using commands like `ls`, `cat /etc/passwd`, or `uname -a`.
5.  The attacker attempts to establish persistence by creating a web shell or modifying system files, such as cron jobs. This allows them to maintain access to the compromised system even after the initial vulnerability is patched.
6.  The attacker downloads additional tools or payloads onto the compromised server using utilities like `curl` or `wget`, often from a remote attacker-controlled server.
7.  The attacker uses the compromised server to pivot to other systems within the network, leveraging gained access to internal resources and sensitive data.
8.  The attacker exfiltrates sensitive data or deploys malware, potentially leading to data breaches, financial loss, or disruption of services.

## Impact

Successful command injection can lead to complete compromise of the web server and potentially the entire network. Attackers can steal sensitive data, modify files, install malware, or use the compromised server as a launchpad for further attacks. The low severity assigned to the original rule may underestimate the true risk if successful exploitation occurs. Depending on the privileges of the web server process, the attacker could gain root access. The number of victims and sectors targeted depends on the specific vulnerability and the attacker's objectives.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM and tune it to your environment, focusing on reducing false positives by excluding known legitimate uses of command-like strings (e.g., documentation or code rendering) in web requests.
*   Investigate any alerts generated by the Sigma rule by examining the raw HTTP request or PCAP, decoding URL and base64-encoded parameters, and identifying shell metacharacters, commands, IP:port pairs, file paths, and download URLs.
*   Implement input validation and sanitization on all web application endpoints to prevent command injection vulnerabilities (reference: this brief's overview).
*   Apply virtual patches or WAF rules to block URLs containing suspicious patterns such as `bash -c`, `/dev/tcp`, `base64 -d`, `curl`, or `nc` (reference: overview).
*   Harden web servers by running them under least privilege, restricting egress traffic, and deploying host sensors to detect suspicious activity like webshell creation (reference: overview).
