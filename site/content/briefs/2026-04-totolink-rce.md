---
title: Totolink A8000RU OS Command Injection Vulnerability
slug: 2026-04-totolink-rce
description: CVE-2026-7152 is a critical OS command injection vulnerability in the Totolink A8000RU router that allows remote attackers to execute arbitrary commands by manipulating the telnet_enabled argument in the setTelnetCfg function.
date: "2026-04-27T20:16:29Z"
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

A critical vulnerability, CVE-2026-7152, has been discovered in the Totolink A8000RU router, specifically version 7.1cu.643_b20200521. This flaw resides within the CGI handler component, affecting the `setTelnetCfg` function located in `/cgi-bin/cstecgi.cgi`. By manipulating the `telnet_enabled` argument, an attacker can inject arbitrary OS commands. This vulnerability is remotely exploitable and poses a significant threat as a proof-of-concept exploit is publicly available. Successful…
