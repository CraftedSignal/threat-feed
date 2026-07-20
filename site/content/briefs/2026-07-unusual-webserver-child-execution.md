---
title: Unusual Child Process Execution by Web Servers on Linux
slug: 2026-07-unusual-webserver-child-execution
description: This detection rule identifies suspicious child process executions originating from web server processes on Linux systems, indicating that attackers may have exploited web application vulnerabilities such as command injection or remote file inclusion to establish persistence or execute malicious commands.
date: "2026-07-20T11:50:58Z"
lastmod: "2026-07-20T20:24:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - execution
  - command-and-control
  - initial-access
  - linux
  - webserver
  - webshell
  - privilege-escalation
  - suid
  - sgid
  - threat-detection
  - endpoint
vendors:
  - Elastic
  - Digium
  - Caddy
  - LiteSpeed Technologies
  - NGINX
  - Apache Software Foundation
  - PHP Group
  - Python Software Foundation
  - Ruby Community
  - Perl Foundation
  - Oracle
  - Atlassian
  - Caucho Technology
  - Google
  - IBM
  - Eclipse Foundation
  - Red Hat
  - Jenkins
  - Apereo
  - VMware
  - Micronaut Foundation
  - Vert.x Community
  - Dropwizard Community
  - Microsoft
  - GitHub
  - Azure
products:
  - Elastic Defend
  - Apache HTTP Server
  - Apache Tomcat
  - NGINX
  - Caddy Server
  - Asterisk
  - LiteSpeed Web Server
  - PHP-FPM
  - PHP-CGI
  - Gunicorn
  - Uvicorn
  - Flask
  - Django
  - Hypercorn
  - Waitress
  - Passenger
  - Puma
  - Rails
  - Starman
  - Plackup
  - Jira
  - Bitbucket Server
  - Resin
  - Gerrit Daemon
  - IBM WebSphere Application Server
  - GlassFish Server
  - Eclipse Jetty
  - Elasticsearch
  - JBoss Application Server
  - Oracle WebLogic Server
  - Jenkins
  - Apereo CAS
  - Keycloak
  - Spring Boot
  - Helidon
  - Micronaut
  - Quarkus
  - Vert.x
  - Dropwizard
  - Zabbix Server
  - Elastic Agent
  - Kibana
  - Fleet
  - Elastic Cloud
  - Elastic Stack (>= 9.3.0)
  - Elastic General Purpose LLM v2
affected_os:
  - Linux
  - Windows
  - macOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: Attackers may exploit web servers to maintain persistence on a compromised system, often resulting in atypical child process executions.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A common pattern is an attacker exploiting a web app bug, then making nginx, Apache, or a Python app server spawn a shell or script interpreter that downloads tools, runs system commands, or installs a backdoor under the web service context.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: If the web child process launched a shell or interpreter, established outbound command-and-control traffic, modified authentication material, moved laterally, or if sensitive data, production secrets, or customer-facing systems may have been exposed.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This alert flags a Linux web service starting a child program it does not normally launch, which can reveal a compromised application server being used for persistence or follow-on actions. A common pattern is an attacker exploiting a web app bug.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: Adversaries exploit misconfigured SUID/SGID binaries to gain elevated access or persistence. This rule identifies processes running with root privileges but initiated by non-root users, flagging potential misuse of SUID/SGID permissions.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_webserver_unusual_child_execution.toml
  - https://attack.mitre.org/techniques/T1548/
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/privilege_escalation_potential_suid_sgid_exploitation.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/initial_access_exfiltration_new_usb_device_mounted.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/command_and_control_curl_activity_llm_triage.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/command_and_control_wget_activity_llm_triage.toml
iocs:
  - type: ip
    value: 0.0.0.0
  - type: ip
    value: 169.254.169.254
  - type: ip
    value: 168.63.129.16
  - type: domain
    value: mcr.microsoft.com
  - type: domain
    value: acs-mirror.azureedge.net
  - type: domain
    value: packages.aks.azure.com
  - type: domain
    value: packages.microsoft.com
  - type: domain
    value: login.microsoftonline.com
  - type: domain
    value: management.azure.com
  - type: domain
    value: storage.googleapis.com
  - type: domain
    value: api.github.com
  - type: domain
    value: artifacts.elastic.co
  - type: domain
    value: download.elastic.co
ioc_counts:
  domain: 10
  ip: 3
rules:
  - title: Detect Unusual Child Execution by Web Server Process on Linux
    description: Detects web server processes spawning unusual child processes, which can indicate compromise through vulnerabilities like command injection or remote file inclusion, used for persistence or further execution.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
      - initial_access
      - persistence
    techniques:
      - T1059
      - T1059.004
      - T1071
      - T1190
      - T1505
      - T1505.003
    data_sources:
      - process_creation
      - linux
  - title: Detect Potential SUID/SGID Privilege Escalation on Linux
    description: Detects potential privilege escalation under the root effective user or group when the real user or parent user/group are not root, indicative of the execution of binaries with SUID or SGID bits set. This rule filters for suspicious parent processes and excludes known legitimate SUID/SGID binaries.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548
      - T1548.001
      - T1548.003
    data_sources:
      - process_creation
      - linux
rules_count: 2
updates:
  - at: "2026-07-20T12:42:22Z"
    level: L2
    summary: 'added detection rule: Detect Potential SUID/SGID Privilege Escalation on Linux'
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/linux/privilege_escalation_potential_suid_lpe_via_process_args.toml
  - at: "2026-07-20T12:42:32Z"
    level: L1
    summary: new product
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/linux/privilege_escalation_potential_suid_sgid_exploitation.toml
  - at: "2026-07-20T13:07:12Z"
    level: L1
    summary: OS windows; OS macos
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/initial_access_exfiltration_new_usb_device_mounted.toml
  - at: "2026-07-20T20:23:13Z"
    level: L1
    summary: new product
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/command_and_control_curl_activity_llm_triage.toml
  - at: "2026-07-20T20:24:38Z"
    level: L1
    summary: new IOCs
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/command_and_control_wget_activity_llm_triage.toml
---

This brief describes a detection mechanism designed to identify unusual child process executions spawned by web server processes on Linux systems. Attackers frequently exploit vulnerabilities in internet-facing web applications, such as command injection, remote file inclusion, or deserialization flaws, to gain initial access and establish persistence. Once a web server (e.g., Apache, NGINX, or various application servers like those based on Python, Ruby, or Java) is compromised, attackers often leverage its privileges to launch atypical child processes. These child processes might include shells, script interpreters, downloaders like `curl` or `wget`, or archive utilities, which deviate significantly from the web server's normal operational behavior. Such activity serves as a strong indicator that the system has been compromised and is being used for further malicious actions like installing backdoors, exfiltrating data, or deploying additional tooling.

## Attack Chain

1. **Initial Access**: An attacker exploits a vulnerability (e.g., command injection, remote file inclusion, deserialization flaw) in a public-facing web application running on a Linux server.
2. **Web Server Process Execution**: The successful exploit causes the compromised web server process (e.g., `nginx`, `apache2`, `php-fpm`, `java` for a Java application server) to spawn an unusual child process.
3. **Command and Scripting Interpreter Execution**: The child process is typically a shell (`bash`, `sh`), a scripting interpreter (`python`, `perl`, `ruby`), or a utility designed to execute arbitrary commands.
4. **Payload Delivery**: The newly spawned child process executes commands to download additional tools or payloads from attacker-controlled infrastructure using utilities like `curl` or `wget`.
5. **Persistence Establishment**: Downloaded tools or executed commands establish persistence mechanisms such as web shells (e.g., in `/var/www/`), new scheduled tasks (cron jobs), modified SSH authorized keys, or system service entries.
6. **Lateral Movement/Data Exfiltration**: The attacker uses the persistent access to perform privilege escalation, collect credentials, move laterally within the network, or exfiltrate sensitive data.
7. **Impact**: The final objective typically involves full system compromise, data breach, or deployment of further malware such as ransomware.

## Impact

Successful exploitation leading to unusual child process execution can result in severe consequences, including full compromise of the affected web server and potentially the broader network. Attackers can leverage the compromised web server's context to install backdoors, escalate privileges, exfiltrate sensitive data, or deploy ransomware. This can lead to significant data breaches, disruption of services, reputational damage, and financial losses. The scope of impact extends to any data handled by the web application or accessible from the compromised server. Without timely detection and remediation, attackers can establish long-term persistence and expand their control over the organization's infrastructure.

## Recommendation

* Deploy the Sigma rule "Detect Unusual Child Execution by Web Server Process on Linux" to your SIEM and tune for your environment to identify deviations from normal web server behavior.
* Review the full parent-to-descendant execution chain for alerts generated by `process_creation` logs from Linux endpoints to understand the sequence of actions.
* Correlate process start times with `webserver` access, error, reverse-proxy, and WAF logs to identify the triggering request, source IP, requested path, and signs of exploitation like command injection.
* Examine activity under the web service account (e.g., `process.parent.name` related accounts) around the alert for suspicious file writes, new scheduled tasks, privilege escalation attempts, or unusual outbound `network_connection` logs.
* Harden the environment by patching exploited web components, disabling unnecessary script execution from upload and web content directories, enforcing least privilege for web service accounts, and restricting outbound network access.
