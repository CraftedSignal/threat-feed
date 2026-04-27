---
title: Totolink A8000RU OS Command Injection Vulnerability (CVE-2026-7155)
slug: 2026-04-totolink-command-injection
description: CVE-2026-7155 is a critical OS command injection vulnerability in the Totolink A8000RU router that allows remote attackers to execute arbitrary commands by manipulating the 'admpass' argument in the setLoginPasswordCfg function.
date: "2026-04-27T21:16:43Z"
severities:
  - critical
tags:
  - cve-2026-7155
  - command-injection
  - totolink
vendors:
  - Totolink
products:
  - A8000RU 7.1cu.643_b20200521
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-7155
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7155
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_319/README.md
  - https://vuldb.com/vuln/359754
rules:
  - title: Detect Totolink A8000RU Command Injection Attempt
    description: Detects attempts to exploit the command injection vulnerability (CVE-2026-7155) in Totolink A8000RU via suspicious POST requests to cstecgi.cgi
    platform: sigma
    severity: critical
    tactics:
      - execution
      - mitre_cve_2026_7155
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink A8000RU setLoginPasswordCfg Command Injection
    description: Detects potential exploitation of CVE-2026-7155 by looking for suspicious characters or commands within the 'admpass' parameter in requests to 'cstecgi.cgi'.
    platform: sigma
    severity: high
    tactics:
      - execution
      - mitre_cve_2026_7155
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, identified as CVE-2026-7155, affects the Totolink A8000RU router, specifically version 7.1cu.643_b20200521. This vulnerability resides within the CGI Handler component, in the `setLoginPasswordCfg` function of the `/cgi-bin/cstecgi.cgi` file. By manipulating the `admpass` argument, a remote attacker can inject arbitrary operating system commands. The vulnerability is remotely exploitable without authentication. Given the availability of a public exploit, this poses a…
