---
title: Totolink A7100RU OS Command Injection Vulnerability (CVE-2026-6115)
slug: 2026-04-totolink-cmd-injection
description: A remote attacker can exploit CVE-2026-6115 in Totolink A7100RU version 7.4cu.2313_b20191024 to inject OS commands by manipulating the 'enable' argument of the setAppCfg function in /cgi-bin/cstecgi.cgi, potentially leading to full system compromise.
date: "2026-04-12T05:16:00Z"
severities:
  - critical
tags:
  - cve-2026-6115
  - totolink
  - command injection
  - router
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-6115
    cvss: 9.8
    epss: 0.01254
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6115
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_180/README.md
  - https://vuldb.com/vuln/356975
rules:
  - title: Detect OS Command Injection Attempt via cstecgi.cgi
    description: Detects potential OS command injection attempts targeting the cstecgi.cgi endpoint by looking for shell command syntax.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect cstecgi.cgi access with suspicious User-Agent
    description: Detects access to cstecgi.cgi with unusual User-Agent strings, potentially indicating automated exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-6115 is a critical OS command injection vulnerability affecting Totolink A7100RU routers running firmware version 7.4cu.2313_b20191024. The vulnerability resides in the `setAppCfg` function within the `/cgi-bin/cstecgi.cgi` CGI handler. An unauthenticated, remote attacker can exploit this vulnerability by crafting a malicious request that injects OS commands into the `enable` argument. This allows the attacker to execute arbitrary commands on the underlying operating system of the…
