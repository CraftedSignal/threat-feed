---
title: Totolink A7100RU OS Command Injection via setTelnetCfg
slug: 2026-04-totolink-rce
description: CVE-2026-5994 describes a critical OS command injection vulnerability in the Totolink A7100RU router (version 7.4cu.2313_b20191024) allowing remote attackers to execute arbitrary commands by manipulating the 'telnet_enabled' argument in the /cgi-bin/cstecgi.cgi CGI handler, with a public exploit available.
date: "2026-04-10T01:19:14Z"
severities:
  - critical
tags:
  - cve-2026-5994
  - command-injection
  - totolink
  - router
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5994
    cvss: 9.8
    epss: 0.01254
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5994
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_166/README.md
  - https://vuldb.com/vuln/356548
rules:
  - title: Detect Totolink A7100RU Command Injection Attempt
    description: Detects attempts to exploit the command injection vulnerability (CVE-2026-5994) in Totolink A7100RU routers by monitoring requests to the /cgi-bin/cstecgi.cgi endpoint with suspicious parameters.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink A7100RU Telnet Enable Command Injection
    description: Detects command injection attempts via the telnet_enabled parameter targeting Totolink A7100RU routers, focusing on common command injection payloads.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical security vulnerability, identified as CVE-2026-5994, exists in the Totolink A7100RU router, specifically version 7.4cu.2313_b20191024. The flaw lies within the `setTelnetCfg` function of the `/cgi-bin/cstecgi.cgi` CGI handler. By manipulating the `telnet_enabled` argument, a remote attacker can inject and execute arbitrary operating system commands on the device. This vulnerability allows unauthenticated attackers to gain full control of the affected router. The existence of a…
