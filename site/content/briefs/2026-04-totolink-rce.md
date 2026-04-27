---
title: Totolink A7100RU OS Command Injection Vulnerability
slug: 2026-04-totolink-rce
description: Totolink A7100RU version 7.4cu.2313_b20191024 is vulnerable to OS command injection via the setTracerouteCfg function in the /cgi-bin/cstecgi.cgi file, allowing remote attackers to execute arbitrary commands by manipulating the 'command' argument.
date: "2026-04-13T12:00:00Z"
severities:
  - critical
tags:
  - cve-2026-6131
  - command-injection
  - router
  - totolink
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-6131
    cvss: 9.8
    epss: 0.01254
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6131
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_182/README.md
  - https://vuldb.com/vuln/356995
rules:
  - title: Detect Totolink A7100RU Command Injection Attempt
    description: Detects potential command injection attempts targeting the setTracerouteCfg function in Totolink A7100RU routers.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect suspicious characters in web requests to cstecgi.cgi
    description: Detects suspicious characters in web requests to cstecgi.cgi which could indicate a command injection attempt
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-6131, has been identified in Totolink A7100RU router firmware version 7.4cu.2313_b20191024. This flaw resides within the CGI Handler component, specifically affecting the `setTracerouteCfg` function in the `/cgi-bin/cstecgi.cgi` file. The vulnerability allows for OS command injection by manipulating the `command` argument. Given that the exploit is publicly available, attackers can remotely execute arbitrary commands on affected devices. This poses a…
