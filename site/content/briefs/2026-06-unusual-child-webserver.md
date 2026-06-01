---
title: Unusual Child Process Execution from Linux Web Servers
slug: 2026-06-unusual-child-webserver
description: This rule detects unusual child process executions originating from web server processes on Linux systems, which attackers may use to maintain persistence on a compromised system by exploiting web server vulnerabilities.
date: "2026-06-01T16:46:51Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - persistence
  - execution
  - command_and_control
  - initial_access
  - linux
  - webserver
vendors:
  - Elastic
  - Atlassian
  - Caucho
  - Google
  - IBM
  - Sun
  - Dropwizard
  - Helidon
  - Micronaut
  - Quarkus
  - Vertx
  - Apache
  - Eclipse
  - Elasticsearch
  - JBoss
  - Play Framework
  - Oracle
  - Apereo
  - Keycloak
  - Spring
products:
  - Jira
  - Resin
  - Gerrit
  - WebSphere
  - GlassFish
  - Dropwizard
  - Helidon
  - Micronaut
  - Quarkus
  - Vert.x
  - Tomcat
  - Jetty
  - Elasticsearch
  - WildFly
  - Play Framework
  - WebLogic Server
  - Bitbucket
  - Jenkins
  - CAS
  - Keycloak
  - Spring Boot
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
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_webserver_unusual_child_execution.toml
  - https://attack.mitre.org/techniques/T1505/
  - https://attack.mitre.org/techniques/T1505/003/
  - https://attack.mitre.org/tactics/TA0003/
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1059/004/
  - https://attack.mitre.org/tactics/TA0002/
  - https://attack.mitre.org/techniques/T1071/
  - https://attack.mitre.org/tactics/TA0011/
  - https://attack.mitre.org/techniques/T1190/
  - https://attack.mitre.org/tactics/TA0001/
rules:
  - title: Detect Unusual Child Processes of Web Servers
    description: Detects unusual child processes spawned by common web server processes on Linux systems. This rule helps identify potential web shell activity or unauthorized command execution originating from compromised web applications.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
      - persistence
    techniques:
      - T1059
      - T1190
      - T1505
    data_sources:
      - process_creation
      - linux
  - title: Detect Web Shell Activity via Process Monitoring
    description: Detects potential web shell activity by monitoring for the execution of common shell interpreters (bash, sh, zsh) as child processes of web server applications (Apache, Nginx, etc.).
    platform: sigma
    severity: high
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

Attackers may exploit vulnerabilities in web servers to gain initial access and establish persistence on compromised Linux systems. This involves leveraging web server processes to execute commands or scripts, often resulting in unusual child process executions. These child processes can be used to download malicious tools, execute system commands, or install backdoors under the web service context. Detecting these deviations from normal web server behavior is critical for identifying compromised systems. This detection focuses on Linux systems and a wide array of web server software.

## Attack Chain

1.  The attacker exploits a vulnerability in a public-facing web application (e.g., command injection, remote file inclusion).
2.  The web server (e.g., Apache, Nginx) executes a malicious command or script as a child process.
3.  The child process spawns a shell (e.g., bash, sh) or interpreter (e.g., python, perl) such as /bin/bash.
4.  The shell downloads additional malicious tools or payloads from a remote server using utilities like `curl` or `wget`.
5.  The downloaded payload is executed, establishing persistence on the system, such as adding a cron job.
6.  The attacker leverages the established persistence to maintain access and perform further malicious activities.
7.  The attacker attempts privilege escalation to gain root access.
8.  The attacker establishes command and control (C2) communication to remotely control the compromised server.

## Impact

Successful exploitation and persistence can lead to a wide range of impacts, including data theft, system compromise, and further lateral movement within the network. A compromised web server can be used to host malicious content, launch attacks against other systems, or exfiltrate sensitive data. The targeted sectors are broad, encompassing any organization that relies on web-based applications and services.

## Recommendation

*   Deploy the Sigma rule `Detect Unusual Child Processes of Web Servers` to your SIEM to identify anomalous process executions originating from web server processes.
*   Investigate any alerts generated by the `Detect Web Shell Activity via Process Monitoring` Sigma rule to identify potential web shell deployments.
*   Implement regular vulnerability scanning and patching procedures to address potential web application vulnerabilities.
*   Review and harden web server configurations to minimize the attack surface and prevent unauthorized command execution.
*   Monitor network connections from web servers for suspicious outbound traffic to identify potential C2 communications.
*   Enable process monitoring and audit logging to capture detailed information about process executions and network connections, enabling comprehensive analysis of suspicious activities.
