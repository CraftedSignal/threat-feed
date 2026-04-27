---
title: Totolink A7100RU Command Injection Vulnerability (CVE-2026-5691)
slug: 2026-04-totolink-command-injection
description: A remote command injection vulnerability affects Totolink A7100RU version 7.4cu.2313_b20191024 allowing unauthenticated attackers to execute arbitrary commands on the device via the setFirewallType function.
date: "2026-04-06T23:16:32Z"
severities:
  - critical
tags:
  - command-injection
  - totolink
  - cve-2026-5691
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5691
    cvss: 7.3
    epss: 0.03903
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5691
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_189/README.md
  - https://vuldb.com/vuln/355518
rules:
  - title: Detect Totolink Command Injection Attempt via firewallType
    description: Detects potential command injection attempts targeting the Totolink A7100RU setFirewallType function by looking for suspicious characters or commands in the firewallType parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect POST to cstecgi.cgi with Common Command Injection Payloads
    description: Detects POST requests to cstecgi.cgi containing common command injection payloads.
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

A critical command injection vulnerability, CVE-2026-5691, has been identified in Totolink A7100RU routers running firmware version 7.4cu.2313_b20191024. The vulnerability resides within the `setFirewallType` function of the `/cgi-bin/cstecgi.cgi` script. A remote, unauthenticated attacker can exploit this flaw by manipulating the `firewallType` argument to inject and execute arbitrary operating system commands on the vulnerable device. Publicly available exploits exist, increasing the urgency…
