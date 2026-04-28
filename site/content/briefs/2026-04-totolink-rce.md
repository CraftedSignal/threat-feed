---
title: Totolink A8000RU Remote Command Injection Vulnerability
slug: 2026-04-totolink-rce
description: Totolink A8000RU version 7.1cu.643_b20200521 is vulnerable to OS command injection via the setPptpServerCfg function in the /cgi-bin/cstecgi.cgi file, allowing remote attackers to execute arbitrary commands by manipulating the 'enable' argument.
date: "2026-04-28T01:16:01Z"
severities:
  - critical
tags:
  - command-injection
  - rce
  - cgi
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
  - id: CVE-2026-7204
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7204
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_323/README.md
  - https://vuldb.com/submit/801530
  - https://vuldb.com/vuln/359804
  - https://vuldb.com/vuln/359804/cti
  - https://www.totolink.net/
rules:
  - title: Detect Totolink A8000RU Command Injection Attempt
    description: Detects potential command injection attempts targeting the Totolink A8000RU router via the setPptpServerCfg function.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Process Spawned by Web Server
    description: Detects unusual processes spawned by the web server, potentially indicating successful command injection on Totolink device.
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

A critical vulnerability, CVE-2026-7204, has been identified in Totolink A8000RU routers running firmware version 7.1cu.643_b20200521. The vulnerability lies within the CGI handler component, specifically in the `setPptpServerCfg` function of the `/cgi-bin/cstecgi.cgi` file. By manipulating the `enable` argument, a remote attacker can inject arbitrary OS commands. The vulnerability has been publicly disclosed, meaning exploit code is available. Successful exploitation allows an attacker to gain…
