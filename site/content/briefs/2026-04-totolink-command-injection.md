---
title: Totolink A7100RU OS Command Injection Vulnerability (CVE-2026-5975)
slug: 2026-04-totolink-command-injection
description: A remote OS command injection vulnerability exists in the setDmzCfg function of the /cgi-bin/cstecgi.cgi file in Totolink A7100RU version 7.4cu.2313_b20191024, allowing attackers to execute arbitrary commands by manipulating the wanIdx argument.
date: "2026-04-09T20:16:29Z"
severities:
  - critical
tags:
  - cve-2026-5975
  - command-injection
  - totolink
  - router
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5975
    cvss: 9.8
    epss: 0.01254
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5975
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_161/README.md
  - https://vuldb.com/submit/791821
  - https://vuldb.com/vuln/356529
  - https://vuldb.com/vuln/356529/cti
  - https://www.totolink.net/
ioc_counts:
  url: 5
rules:
  - title: Detect Totolink Command Injection Attempt via wanIdx
    description: Detects attempts to exploit the Totolink command injection vulnerability by looking for shell metacharacters in the wanIdx parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Outbound Connection from Totolink After Exploitation
    description: Detects outbound network connections from a Totolink router after a potential command injection attempt.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

CVE-2026-5975 details an OS command injection vulnerability affecting Totolink A7100RU router version 7.4cu.2313_b20191024. The flaw resides within the setDmzCfg function of the /cgi-bin/cstecgi.cgi component, specifically in how it handles the `wanIdx` argument. A remote attacker can exploit this vulnerability by injecting arbitrary OS commands, potentially gaining full control of the affected device. Publicly available exploits exist, increasing the risk of widespread exploitation. This…
