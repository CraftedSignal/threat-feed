---
title: Suspicious Command Execution via Web Server on Linux
slug: 2026-06-persistence-webserver-command-execution
description: Identifies suspicious command executions via a web server on Linux systems, which may suggest a vulnerability and remote shell access.
date: "2026-06-01T16:46:26Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - persistence
  - initial-access
  - vulnerability
  - linux
vendors:
  - Elastic
  - Apache
  - nginx
  - mongrel_rails
  - uwsgi
  - daphne
  - flask
  - LightSpeed
  - varnish
  - Tomcat
  - Jetty
  - Red Hat
  - JBoss
  - WebLogic
  - IBM
  - GlassFish
  - Resin
  - Spring
  - Quarkus
  - Micronaut
  - Dropwizard
  - Play
  - Helidon
  - Vert.x
  - Keycloak
  - Apereo
  - Google
  - Atlassian
  - Gerrit
  - Solr
  - Jenkins
products:
  - Elastic Defend
  - apache2
  - nginx
  - httpd
  - caddy
  - mongrel_rails
  - uwsgi
  - daphne
  - flask
  - php-cgi
  - php-fcgi
  - php-cgi.cagefs
  - lswsctrl
  - varnishd
  - uvicorn
  - waitress-serve
  - starman
  - frankenphp
  - zabbix_server
  - asterisk
  - sw-engine-fpm
  - Tomcat
  - Jetty
  - WildFly
  - WebLogic
  - WebSphere
  - Liberty
  - GlassFish
  - Resin
  - Spring Boot
  - Quarkus
  - Micronaut
  - Dropwizard
  - Play
  - Helidon
  - Vert.x
  - Keycloak
  - Apereo CAS
  - Elasticsearch
  - Jira
  - Bitbucket
  - Gerrit
  - Solr
  - Jenkins
affected_os:
  - Linux
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
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_webserver_suspicious_command_execution.toml
rules:
  - title: Detect Suspicious Command Execution via Web Server
    description: Detects suspicious commands executed by a web server on Linux systems indicating potential exploitation.
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
  - title: Detect Web Shell Creation via Web Server
    description: Detects the creation of web shells in common web server directories.
    platform: sigma
    severity: low
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
rules_count: 2
---

This detection identifies suspicious command executions originating from web server processes on Linux systems. Attackers may exploit vulnerabilities in web applications to execute commands, potentially leading to the deployment of backdoors for persistent access. The rule focuses on detecting shell commands executed by web server processes (e.g., nginx, Apache) that exhibit characteristics commonly associated with exploitation attempts, such as discovery commands, credential access, payload decoding, or reverse shell setup. This activity is anomalous because web servers typically do not need to spawn shell commands, thus warranting further investigation.

## Attack Chain

1. An attacker identifies a vulnerability in a web application running on a Linux server.
2. The attacker crafts a malicious HTTP request to exploit the vulnerability, injecting a command into a vulnerable parameter or input field.
3. The web server process (e.g., nginx, Apache) executes the injected command via a shell interpreter (e.g., bash, sh).
4. The executed command performs reconnaissance activities, such as reading system files (/etc/passwd, /etc/shadow) or enumerating network configurations (/etc/hosts, /etc/resolv.conf).
5. The attacker leverages encoding techniques (e.g., base64) to obfuscate malicious payloads or commands within the exploited application.
6. The attacker establishes a reverse shell connection to an external attacker-controlled server using tools like netcat or socat.
7. The attacker modifies system files, such as cron jobs or SSH authorized keys, to establish persistence on the compromised system.
8. The attacker deploys a web shell or backdoor file in the web server's document root, enabling future code execution.

## Impact

A successful attack could lead to unauthorized access to sensitive data, system compromise, and persistent control of the web server. This may result in data breaches, service disruption, and further lateral movement within the compromised network. The severity depends on the exploited vulnerability and the attacker's objectives.

## Recommendation

*   Deploy the Sigma rule "Detect Suspicious Command Execution via Web Server" to your SIEM and tune for your environment.
*   Enable Elastic Defend integration to monitor process executions.
*   Review and harden web application configurations to prevent command injection vulnerabilities.
*   Implement strong input validation and output encoding mechanisms in web applications.
*   Regularly scan web applications for vulnerabilities and apply necessary patches.
