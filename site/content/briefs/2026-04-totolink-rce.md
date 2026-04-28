---
title: Totolink A8000RU OS Command Injection Vulnerability
slug: 2026-04-totolink-rce
description: Totolink A8000RU version 7.1cu.643_b20200521 is vulnerable to OS command injection via the setWiFiWpsStart function in the /cgi-bin/cstecgi.cgi CGI handler, allowing remote attackers to execute arbitrary commands by manipulating the wscDisabled argument.
date: "2026-04-28T01:16:01Z"
severities:
  - critical
tags:
  - cve-2026-7202
  - command-injection
  - router
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
  - id: CVE-2026-7202
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7202
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_321/README.md
  - https://vuldb.com/submit/801527
  - https://vuldb.com/vuln/359802
  - https://vuldb.com/vuln/359802/cti
  - https://www.totolink.net/
rules:
  - title: Detect Totolink A8000RU Command Injection Attempt via cstecgi.cgi
    description: Detects potential command injection attempts targeting the setWiFiWpsStart function in Totolink A8000RU routers by identifying suspicious characters in the wscDisabled parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink A8000RU Command Injection Attempt via User Agent
    description: Detects potential command injection attempts targeting the setWiFiWpsStart function in Totolink A8000RU routers by identifying suspicious characters in the User Agent header, which might indicate an attacker attempting to bypass other security measures.
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

A critical vulnerability, CVE-2026-7202, has been identified in Totolink A8000RU router firmware version 7.1cu.643_b20200521. The vulnerability resides within the CGI Handler component, specifically in the `setWiFiWpsStart` function of the `/cgi-bin/cstecgi.cgi` file. By manipulating the `wscDisabled` argument, a remote attacker can inject and execute arbitrary operating system commands on the affected device. This vulnerability is remotely exploitable without authentication and has a public…
