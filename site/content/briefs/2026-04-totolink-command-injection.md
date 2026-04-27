---
title: Totolink A7100RU Command Injection Vulnerability
slug: 2026-04-totolink-command-injection
description: Totolink A7100RU version 7.4cu.2313_b20191024 is vulnerable to command injection due to improper neutralization of special elements within the setLedCfg function in the /cgi-bin/cstecgi.cgi file, allowing a remote attacker to execute arbitrary commands.
date: "2026-04-12T23:16:25Z"
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

A command injection vulnerability exists in Totolink A7100RU router with firmware version 7.4cu.2313_b20191024. The vulnerability resides within the CGI handler component, specifically in the `/cgi-bin/cstecgi.cgi` file's `setLedCfg` function. By manipulating the `enable` argument, an attacker can inject and execute arbitrary operating system commands on the affected device. This vulnerability is remotely exploitable without authentication and has a publicly available exploit, making it a…
