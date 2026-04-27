---
title: Totolink A8000RU OS Command Injection Vulnerability (CVE-2026-7154)
slug: 2024-01-totolink-a8000ru-command-injection
description: A remote OS command injection vulnerability exists in the Totolink A8000RU router version 7.1cu.643_b20200521, allowing attackers to execute arbitrary commands by manipulating the 'tty_server' argument in the 'setAdvancedInfoShow' function.
date: "2024-01-23T12:00:00Z"
severities:
  - critical
exploited: true
tags:
  - cve-2026-7154
  - command-injection
  - network-device
vendors:
  - Totolink
products:
  - A8000RU 7.1cu.643_b20200521
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7154
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7154
rules:
  - title: Detect Suspicious Totolink CGI Request
    description: Detects potential exploitation attempts of command injection vulnerabilities in Totolink devices by monitoring HTTP requests to cstecgi.cgi with suspicious payloads.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1202
    data_sources:
      - webserver
      - linux
  - title: Detect Shell Spawn from Web Server Process
    description: Detects the execution of shell processes (sh, bash, etc.) spawned by the web server process (httpd, nginx, etc.) indicating potential command injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-7154 describes a critical vulnerability affecting the Totolink A8000RU router, specifically version 7.1cu.643_b20200521. The vulnerability is located in the `setAdvancedInfoShow` function within the `/cgi-bin/cstecgi.cgi` file, which handles CGI requests. An attacker can remotely exploit this flaw by manipulating the `tty_server` argument, leading to OS command injection. This means an unauthenticated attacker can potentially execute arbitrary commands on the underlying operating…
