---
title: choieastsea simple-openstack-mcp OS Command Injection Vulnerability (CVE-2026-7066)
slug: 2024-01-simple-openstack-mcp-command-injection
description: The choieastsea simple-openstack-mcp application is vulnerable to OS command injection via the exec_openstack function in server.py, allowing remote attackers to execute arbitrary commands.
date: "2024-01-02T12:00:00Z"
severities:
  - high
tags:
  - command-injection
  - vulnerability
  - openstack
products:
  - simple-openstack-mcp
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7066
    cvss: 7.3
    epss: 0.01039
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7066
rules:
  - title: Detect Potential Command Injection Attempts in simple-openstack-mcp
    description: This rule detects requests to the server.py endpoint with suspicious parameters indicative of command injection attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Processes Spawned by Web Server
    description: This rule detects processes spawned by the web server user that are commonly used for malicious purposes.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Outbound Network Connections from Web Server to Non-Standard Ports
    description: This rule detects network connections from the web server process to unusual destination ports, potentially indicating command and control activity following a successful exploit.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 3
---

A critical vulnerability, identified as CVE-2026-7066, has been discovered in choieastsea simple-openstack-mcp up to version 767b2f4a8154cca344344b9725537a58399e6036. This vulnerability resides within the `exec_openstack` function of the `server.py` file. Due to insufficient input sanitization, a remote attacker can inject arbitrary OS commands. The exploit is publicly available, increasing the risk of exploitation. The vendor utilizes rolling releases, so specific affected versions are…
