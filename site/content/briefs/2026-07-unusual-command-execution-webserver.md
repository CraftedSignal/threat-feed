---
title: Unusual Command Execution via Linux Web Server Processes
slug: 2026-07-unusual-command-execution-webserver
description: This brief details how attackers exploit vulnerable web applications or deploy webshells on Linux systems to achieve persistence by executing unusual shell commands from web server processes, potentially leading to payload downloads, reverse shells, or cron-like task implants.
date: "2026-07-20T11:45:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - linux-threat
  - persistence
  - web-exploitation
  - webshell
  - command-execution
  - detection-rule
  - elastic-security
vendors:
  - Apache Software Foundation
  - Nginx
  - LiteSpeed Technologies
  - Oracle
  - Atlassian
  - IBM
  - Eclipse Foundation
  - Elastic
  - Digium
  - Zabbix LLC
  - CloudBees
  - Broadcom
  - Caucho Technology
  - Google
  - Lightbend
  - Micronaut Foundation
  - Phusion
  - Caddy Server
products:
  - Apache HTTP Server
  - Apache Tomcat
  - Apache Solr
  - Nginx
  - PHP-CGI
  - PHP-FPM
  - LiteSpeed Web Server
  - LiteSpeed PHP
  - Gunicorn
  - Uvicorn
  - Daphne
  - Flask
  - Waitress
  - Ruby on Rails
  - Puma
  - Passenger
  - Plack
  - Atlassian Jira
  - Resin
  - Google Gerrit
  - IBM WebSphere Application Server
  - GlassFish Server
  - Dropwizard
  - Helidon
  - Micronaut
  - Quarkus
  - Eclipse Vert.x
  - Jetty
  - Elasticsearch
  - JBoss Application Server
  - Play Framework
  - Oracle WebLogic Server
  - Atlassian Bitbucket Server
  - Jenkins
  - Apereo CAS
  - Keycloak
  - Spring Boot
  - Caddy
  - Asterisk
  - Varnish Cache
  - Zabbix Server
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: Attackers may exploit web servers to maintain persistence on a compromised system, often resulting in atypical command executions.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This rule detects shells invoked by web server processes on Linux to run one-off commands, surfacing command lines the server has never executed before.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Correlate with network telemetry to see if the web tier opened outbound connections or listeners (nc, bash -i, curl/wget), and capture any active sockets and destinations for rapid containment.
    confidence_band: med
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers exploit vulnerable apps or dropped webshells to launch bash -c from web roots, e.g., download a payload with wget/curl into /opt or /tmp, chmod +x and execute it, or open a reverse shell (nc -e sh) to implant services or cron-like tasks and persist under the web server account.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_webserver_unusual_command_execution.toml
rules:
  - title: Detect Shell Execution by Linux Web Server Processes
    description: Detects the execution of shell commands by known web server processes, which can indicate webshell activity, exploitation, or persistence mechanisms on a compromised Linux system. This rule aims to identify potentially malicious deviations from normal web server behavior.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
      - persistence
    techniques:
      - T1059
      - T1059.004
      - T1190
      - T1505
      - T1505.003
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

Attackers frequently leverage compromised Linux web servers as a persistent foothold within an organization's network. This threat involves the exploitation of vulnerable web applications or the deployment of webshells, which then enable the web server process (such as Apache, Nginx, or various application servers like Tomcat or JBoss) to execute arbitrary shell commands. These commands are often "unusual" in the sense that they represent atypical behavior for a web server, indicating malicious activity rather than legitimate web operations. Such command executions can be used to download additional malware (e.g., using `wget` or `curl`), establish reverse shells for command and control (e.g., `netcat -e sh`), or implant new services or cron jobs for long-term persistence. The detection of these activities is crucial as they signify a compromised host that could be used for further lateral movement, data exfiltration, or system-wide impact.

## Attack Chain

1. **Initial Access**: An attacker exploits a vulnerability in a public-facing web application (e.g., RCE, file upload vulnerability) or drops a webshell onto a web server.
2. **Execution via Web Server**: The compromised web server process (e.g., Apache, Nginx, PHP-FPM, or a Java application server) is leveraged to execute a shell command, often using `bash -c` or similar, to bypass restrictions.
3. **Payload Download**: The executed shell command initiates the download of secondary payloads or tools from attacker-controlled infrastructure using utilities like `wget` or `curl`.
4. **Local Execution**: Downloaded binaries or scripts are made executable (e.g., `chmod +x`) and then executed from temporary directories or other locations.
5. **Command and Control**: The attacker establishes a reverse shell (e.g., `nc -e sh /bin/bash`) back to their C2 server to gain interactive control over the compromised web server.
6. **Persistence Establishment**: Malicious scripts or binaries modify system services, cron jobs, or other startup mechanisms (e.g., `systemd` units) to ensure continued execution after reboots or service restarts.
7. **Post-Exploitation Activity**: With persistent access and C2 established, the attacker proceeds with further objectives, which may include data exfiltration, lateral movement, or deploying ransomware.

## Impact

Successful exploitation of web servers through unusual command execution can lead to severe consequences for an organization. Compromised web servers often host sensitive data, critical applications, or serve as a gateway to internal networks. Attackers can leverage this access for full system compromise, data theft, defacement of public-facing assets, deployment of ransomware, or using the server as a staging ground for attacks against other internal systems. The impact can include significant financial losses due to data breaches, operational disruption, reputational damage, and the costs associated with incident response and remediation. The persistence techniques deployed can make detection and eradication challenging, prolonging the recovery process.

## Recommendation

* Deploy the Sigma rule in this brief to your SIEM and tune for your environment to detect shell execution from web server parent processes.
* Configure endpoint logging solutions to capture `process_creation` events, especially `process.parent.name`, `process.name`, `process.args`, and `process.command_line` on Linux systems.
* Regularly reconstruct the process tree around suspicious events to identify the full chain of execution and any associated files.
* Monitor web server access and error logs for anomalies such as unusual POST uploads, long query strings, or HTTP 500 errors corresponding to suspicious command execution timestamps.
* Implement file integrity monitoring on common web roots (`/var/www`, `/usr/share/nginx`, `/srv/http`) and application directories to detect newly created or modified files like webshells or backdoors.
* Configure network telemetry to detect unusual outbound connections or listeners initiated by web server processes.
* Harden web servers by disabling risky `exec` functions (e.g., PHP `exec`/`system`/`shell_exec`), enforcing `noexec`, `nodev`, `nosuid` mounts on web roots, and applying SELinux/AppArmor confinement.
