---
title: suvarchal docker-mcp-server Remote OS Command Injection Vulnerability
slug: 2024-01-10-docker-mcp-server-command-injection
description: A remote OS command injection vulnerability exists in suvarchal docker-mcp-server up to version 0.1.0 allowing for arbitrary command execution via the stop_container, remove_container, or pull_image functions within the src/index.ts file.
date: "2024-01-10T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - docker
  - CVE-2026-5741
vendors:
  - suvarchal
products:
  - docker-mcp-server
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5741
    cvss: 7.3
    epss: 0.0212
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5741
rules:
  - title: Detect Suspicious HTTP Requests to docker-mcp-server
    description: Detects potential command injection attempts by monitoring HTTP requests targeting the vulnerable functions in docker-mcp-server.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-5741
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
      - linux
  - title: Detect Shell Execution via Docker MCP Server
    description: Detects potential shell execution originating from the docker-mcp-server process
    platform: sigma
    severity: high
    tactics:
      - cve-2026-5741
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical vulnerability, identified as CVE-2026-5741, affects suvarchal docker-mcp-server versions up to 0.1.0. The vulnerability resides within the `stop_container`, `remove_container`, and `pull_image` functions of the `src/index.ts` file, which constitute the HTTP Interface. Successful exploitation allows for remote OS command injection, granting an attacker the ability to execute arbitrary commands on the host system. Public exploits are available, significantly increasing the risk of widespread exploitation. The project maintainers were notified but have not responded. This lack of response elevates the urgency for defenders to implement detection and mitigation measures to prevent potential breaches.

## Attack Chain

1.  The attacker identifies a vulnerable instance of suvarchal docker-mcp-server running version 0.1.0 or earlier.
2.  The attacker crafts a malicious HTTP request targeting one of the vulnerable functions: `stop_container`, `remove_container`, or `pull_image`.
3.  The malicious request includes specially crafted input designed to inject OS commands. This input is embedded within the parameters expected by the vulnerable functions.
4.  The docker-mcp-server processes the request and passes the attacker-controlled input to the underlying operating system without proper sanitization.
5.  The operating system executes the injected commands, allowing the attacker to perform arbitrary actions on the host.
6.  The attacker gains initial access to the system and can then attempt to escalate privileges.
7.  The attacker establishes persistence through methods like creating new user accounts or modifying system startup scripts.
8.  The attacker moves laterally within the network, compromising additional systems and exfiltrating sensitive data.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary commands on the host system where the docker-mcp-server is running. This can lead to complete system compromise, data theft, and denial of service. Given the nature of docker-mcp-server, compromised systems could provide access to containerized environments, potentially impacting multiple applications and services. The availability of public exploits makes this a high-risk vulnerability, potentially impacting any organization using the affected docker-mcp-server versions.

## Recommendation

*   Monitor web server logs for suspicious HTTP requests targeting the `stop_container`, `remove_container`, and `pull_image` functions (see example Sigma rule below).
*   Implement strict input validation and sanitization on any applications or services using docker-mcp-server.
*   Apply patches or updates to docker-mcp-server as soon as they become available to address CVE-2026-5741.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect exploitation attempts.
