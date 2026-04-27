---
title: Totolink A7100RU OS Command Injection Vulnerability (CVE-2026-5677)
slug: 2026-04-totolink-os-command-injection
description: A remote OS command injection vulnerability (CVE-2026-5677) exists in the CsteSystem function of the /cgi-bin/cstecgi.cgi file in Totolink A7100RU firmware version 7.4cu.2313_b20191024 due to improper handling of the resetFlags argument.
date: "2026-04-06T19:16:30Z"
severities:
  - high
tags:
  - cve-2026-5677
  - totolink
  - command-injection
  - network-device
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5677
    cvss: 7.3
    epss: 0.04857
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5677
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_184/README.md
  - https://vuldb.com/vuln/355504
rules:
  - title: Detect Totolink A7100RU CsteSystem Command Injection Attempt
    description: Detects attempts to exploit the CVE-2026-5677 command injection vulnerability in Totolink A7100RU routers by identifying requests to /cgi-bin/cstecgi.cgi with shell metacharacters in the resetFlags parameter.
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
  - title: Detect Totolink A7100RU CsteSystem Access
    description: Detects access to the /cgi-bin/cstecgi.cgi on Totolink A7100RU routers.
    platform: sigma
    severity: low
    tactics:
      - discovery
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical OS command injection vulnerability, tracked as CVE-2026-5677, has been identified in Totolink A7100RU routers running firmware version 7.4cu.2313_b20191024. The vulnerability resides within the `CsteSystem` function of the `/cgi-bin/cstecgi.cgi` file. By manipulating the `resetFlags` argument, a remote attacker can inject and execute arbitrary operating system commands on the affected device. This exploit is publicly available, increasing the risk of widespread exploitation…
