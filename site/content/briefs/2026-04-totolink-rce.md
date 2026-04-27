---
title: Totolink A7100RU Remote Command Injection Vulnerability
slug: 2026-04-totolink-rce
description: A remote command injection vulnerability exists in Totolink A7100RU firmware version 7.4cu.2313_b20191024, allowing unauthenticated attackers to execute arbitrary commands on the device.
date: "2026-04-09T06:16:23Z"
severities:
  - critical
tags:
  - command-injection
  - totolink
  - cve-2026-5850
  - rce
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5850
    cvss: 9.8
    epss: 0.01254
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5850
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_156/README.md
rules:
  - title: Detect Totolink RCE Attempt via Crafted POST Request
    description: Detects attempts to exploit the Totolink A7100RU command injection vulnerability by identifying crafted POST requests to the cstecgi.cgi endpoint with suspicious content in the pptpPassThru parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1202
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink RCE Attempt via Shell command
    description: Detects attempts to exploit the Totolink A7100RU command injection vulnerability by identifying shell commands in the web server logs related to the cstecgi.cgi endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1202
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-5850, has been identified in Totolink A7100RU routers running firmware version 7.4cu.2313_b20191024. The vulnerability lies within the `setVpnPassCfg` function of the `/cgi-bin/cstecgi.cgi` file, which handles CGI requests. An attacker can inject operating system commands by manipulating the `pptpPassThru` argument in a crafted request. The vulnerability is remotely exploitable without authentication, and a proof-of-concept exploit is publicly available…
