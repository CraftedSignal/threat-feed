---
title: Totolink A7100RU OS Command Injection Vulnerability (CVE-2026-5678)
slug: 2026-04-totolink-rce
description: An OS command injection vulnerability (CVE-2026-5678) exists in the setScheduleCfg function of the /cgi-bin/cstecgi.cgi file in Totolink A7100RU firmware version 7.4cu.2313_b20191024, allowing remote attackers to execute arbitrary commands by manipulating the 'mode' argument.
date: "2026-04-06T19:16:30Z"
severities:
  - critical
tags:
  - cve-2026-5678
  - command-injection
  - router
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5678
    cvss: 7.3
    epss: 0.04857
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5678
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_185/README.md
  - https://vuldb.com/vuln/355505
rules:
  - title: Detect Totolink A7100RU Command Injection Attempt via cstecgi.cgi
    description: Detects attempts to exploit the command injection vulnerability (CVE-2026-5678) in Totolink A7100RU routers by monitoring requests to cstecgi.cgi with suspicious 'mode' parameter values.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink A7100RU Firmware Version Check
    description: Detects requests that might be probing for the specific vulnerable firmware version.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-5678, affects Totolink A7100RU routers running firmware version 7.4cu.2313_b20191024. This flaw resides in the `setScheduleCfg` function within the `/cgi-bin/cstecgi.cgi` file, an interface used for managing scheduled tasks on the device. The vulnerability allows unauthenticated remote attackers to inject and execute arbitrary operating system commands on the router. Publicly available exploits exist, increasing the risk of widespread exploitation. Given the…
