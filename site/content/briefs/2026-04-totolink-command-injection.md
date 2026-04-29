---
title: Totolink A7100RU Command Injection Vulnerability
slug: 2026-04-totolink-command-injection
description: Totolink A7100RU version 7.4cu.2313_b20191024 is vulnerable to command injection due to improper neutralization of special elements within the setLedCfg function in the /cgi-bin/cstecgi.cgi file, allowing a remote attacker to execute arbitrary commands.
date: "2026-04-12T23:16:25Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - command-injection
  - router
  - totolink
  - cve-2026-6132
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-6132
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6132
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_183/README.md
  - https://vuldb.com/vuln/356996
rules:
  - title: Detect Totolink A7100RU Command Injection Attempt
    description: Detects potential command injection attempts targeting the Totolink A7100RU router via the cstecgi.cgi endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink A7100RU Reboot Command Injection
    description: Detects reboot command injection attempts targeting the Totolink A7100RU router via the cstecgi.cgi endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A command injection vulnerability exists in Totolink A7100RU router with firmware version 7.4cu.2313_b20191024. The vulnerability resides within the CGI handler component, specifically in the `/cgi-bin/cstecgi.cgi` file's `setLedCfg` function. By manipulating the `enable` argument, an attacker can inject and execute arbitrary operating system commands on the affected device. This vulnerability is remotely exploitable without authentication and has a publicly available exploit, making it a critical risk for users of the specified Totolink A7100RU firmware. This allows attackers to potentially gain complete control of the router.

## Attack Chain

1.  The attacker identifies a vulnerable Totolink A7100RU router running firmware 7.4cu.2313_b20191024.
2.  The attacker crafts a malicious HTTP request targeting the `/cgi-bin/cstecgi.cgi` endpoint.
3.  The attacker injects an OS command into the `enable` argument of the `setLedCfg` function within the CGI request. For example, `enable=;reboot;`.
4.  The webserver processes the CGI request and passes the attacker-controlled `enable` argument to the `setLedCfg` function without proper sanitization.
5.  The injected OS command is executed with the privileges of the web server process.
6.  The attacker achieves arbitrary code execution on the router's operating system.
7.  Depending on the injected command, the attacker can modify router settings, exfiltrate sensitive information, install malware, or cause a denial-of-service condition.
8.  The attacker may use the compromised router as a pivot point for further attacks within the local network or to participate in botnet activities.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the affected Totolink A7100RU router. This could lead to complete compromise of the device, allowing the attacker to modify router configurations, intercept network traffic, or use the router as part of a botnet. Given the wide use of these routers in home and small business networks, a large number of devices could be vulnerable if left unpatched. The CVSS v3.1 score of 9.8 highlights the critical severity of this vulnerability.

## Recommendation

*   Monitor web server logs for requests to `/cgi-bin/cstecgi.cgi` containing suspicious characters or command sequences within the `enable` parameter to detect exploitation attempts (see Sigma rule `Detect Totolink A7100RU Command Injection Attempt`).
*   Apply available firmware updates from Totolink to patch CVE-2026-6132 if available.
*   Implement web application firewall (WAF) rules to filter out malicious requests targeting `/cgi-bin/cstecgi.cgi` and the `enable` parameter.
*   Disable remote administration access to the router to reduce the attack surface.
