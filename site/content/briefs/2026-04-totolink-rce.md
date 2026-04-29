---
title: Totolink A8000RU OS Command Injection Vulnerability
slug: 2026-04-totolink-rce
description: CVE-2026-7152 is a critical OS command injection vulnerability in the Totolink A8000RU router that allows remote attackers to execute arbitrary commands by manipulating the telnet_enabled argument in the setTelnetCfg function.
date: "2026-04-27T20:16:29Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - command-injection
  - rce
  - totolink
vendors:
  - Totolink
products:
  - A8000RU 7.1cu.643_b20200521
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7152
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7152
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_316/README.md
  - https://vuldb.com/vuln/359751
rules:
  - title: Detect Totolink RCE via CGI
    description: Detects attempts to exploit the Totolink A8000RU OS command injection vulnerability (CVE-2026-7152) by monitoring POST requests to the cstecgi.cgi script.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Shell Spawn from Totolink CGI
    description: Detects shell processes spawned from the cstecgi.cgi process, which is indicative of successful command injection.
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

A critical vulnerability, CVE-2026-7152, has been discovered in the Totolink A8000RU router, specifically version 7.1cu.643_b20200521. This flaw resides within the CGI handler component, affecting the `setTelnetCfg` function located in `/cgi-bin/cstecgi.cgi`. By manipulating the `telnet_enabled` argument, an attacker can inject arbitrary OS commands. This vulnerability is remotely exploitable and poses a significant threat as a proof-of-concept exploit is publicly available. Successful exploitation could lead to complete system compromise, allowing attackers to gain full control of the affected router and potentially pivot to other devices on the network.

## Attack Chain

1.  Attacker identifies a Totolink A8000RU router running firmware version 7.1cu.643_b20200521.
2.  Attacker sends a crafted HTTP POST request to `/cgi-bin/cstecgi.cgi`.
3.  The POST request targets the `setTelnetCfg` function.
4.  The request includes a malicious payload within the `telnet_enabled` argument, injecting an OS command.
5.  The `setTelnetCfg` function fails to properly sanitize the `telnet_enabled` argument.
6.  The injected OS command is executed by the router's operating system with elevated privileges.
7.  Attacker gains remote shell access to the router.
8.  Attacker can then perform further malicious activities such as network reconnaissance, data exfiltration, or deploying persistent backdoors.

## Impact

Successful exploitation of CVE-2026-7152 allows an attacker to execute arbitrary OS commands on the affected Totolink A8000RU router. This can lead to a complete compromise of the device, allowing the attacker to modify router configurations, intercept network traffic, or use the router as a pivot point to attack other devices on the network. Given the wide usage of these routers, a successful widespread exploitation could affect thousands of home and business networks.

## Recommendation

*   Deploy the Sigma rule `Detect Totolink RCE via CGI` to detect exploitation attempts in web server logs.
*   Apply available patches or firmware updates from Totolink to remediate CVE-2026-7152.
*   Monitor web server logs for suspicious POST requests to `/cgi-bin/cstecgi.cgi` as indicated in the attack chain.
*   Implement strict input validation and sanitization for all CGI scripts to prevent command injection vulnerabilities (reference the vulnerability description).
