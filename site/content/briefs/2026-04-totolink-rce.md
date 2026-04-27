---
title: Totolink A7100RU OS Command Injection Vulnerability (CVE-2026-6116)
slug: 2026-04-totolink-rce
description: CVE-2026-6116 is an OS command injection vulnerability in Totolink A7100RU version 7.4cu.2313_b20191024, allowing remote attackers to execute arbitrary OS commands by manipulating the 'ip' argument in the setDiagnosisCfg function of the /cgi-bin/cstecgi.cgi CGI handler, with a public exploit available.
date: "2026-04-12T05:16:01Z"
severities:
  - critical
tags:
  - cve-2026-6116
  - command-injection
  - totolink
  - router
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-6116
    cvss: 9.8
    epss: 0.01254
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6116
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_181/README.md
  - https://vuldb.com/vuln/356976
rules:
  - title: Detect Totolink A7100RU Command Injection Attempt
    description: Detects attempts to exploit the Totolink A7100RU command injection vulnerability (CVE-2026-6116) by monitoring for suspicious requests to the /cgi-bin/cstecgi.cgi endpoint with shell metacharacters in the query string.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink A7100RU Command Injection via Web Logs
    description: This rule detects potential command injection attempts in Totolink A7100RU routers by analyzing web server logs for requests to the /cgi-bin/cstecgi.cgi endpoint containing specific patterns indicative of command injection.
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

A critical OS command injection vulnerability, CVE-2026-6116, has been identified in Totolink A7100RU router firmware version 7.4cu.2313_b20191024. The vulnerability resides within the CGI handler component, specifically in the `setDiagnosisCfg` function of the `/cgi-bin/cstecgi.cgi` file. An attacker can remotely exploit this vulnerability by manipulating the `ip` argument, injecting arbitrary OS commands that are then executed by the router's operating system. The public availability of the…
