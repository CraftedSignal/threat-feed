---
title: Totolink A7100RU Command Injection Vulnerability (CVE-2026-5688)
slug: 2026-04-totolink-cmd-injection
description: A remote command injection vulnerability exists in the setDdnsCfg function of the /cgi-bin/cstecgi.cgi file in Totolink A7100RU version 7.4cu.2313_b20191024, allowing attackers to execute arbitrary OS commands by manipulating the provider argument.
date: "2026-04-06T23:16:28Z"
severities:
  - high
tags:
  - command injection
  - router vulnerability
  - Totolink
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5688
    cvss: 7.3
    epss: 0.04857
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5688
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_186/README.md
  - https://vuldb.com/vuln/355515
rules:
  - title: Detect Exploitation Attempts CVE-2026-5688 via Web Logs
    description: Detects potential exploitation attempts of CVE-2026-5688 by looking for suspicious requests to /cgi-bin/cstecgi.cgi with command injection patterns.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-5688
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Outbound Connections from Potentially Compromised Totolink Router
    description: Detects potential data exfiltration attempts from a potentially compromised Totolink router based on user agent and unusual destination ports.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - cve-2026-5688
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - firewall
rules_count: 2
---

A command injection vulnerability, tracked as CVE-2026-5688, affects Totolink A7100RU router firmware version 7.4cu.2313_b20191024. The vulnerability resides in the `setDdnsCfg` function within the `/cgi-bin/cstecgi.cgi` file. By manipulating the `provider` argument, an attacker can inject arbitrary OS commands that will be executed on the router's operating system. The attack can be launched remotely, making it easily exploitable. Publicly available exploits exist, increasing the risk of…
