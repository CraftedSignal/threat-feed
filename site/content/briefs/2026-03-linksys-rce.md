---
title: Linksys MR9600 SmartConnect OS Command Injection (CVE-2026-4558)
slug: 2026-03-linksys-rce
description: A remote OS command injection vulnerability exists in the Linksys MR9600 router version 2.0.6.206937, allowing attackers to execute arbitrary commands by manipulating specific function arguments via the SmartConnect.lua file.
date: "2026-03-23T12:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - CVE-2026-4558
  - linksys
  - command-injection
  - network-device
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4558
  - https://github.com/utmost3/cve/issues/1
  - https://vuldb.com/?ctiid.352385
  - https://vuldb.com/?id.352385
  - https://vuldb.com/?submit.775036
  - https://www.linksys.com/
rules:
  - title: Linksys MR9600 Command Injection Attempt
    description: Detects suspicious HTTP requests attempting to exploit the command injection vulnerability in Linksys MR9600 via SmartConnect.lua
    platform: sigma
    severity: critical
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.004
      - T1071.001
    data_sources:
      - webserver
      - linux
  - title: Linksys MR9600 Network Exploit
    description: Detects network connections associated with potential exploitation of Linksys MR9600 command injection.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - firewall
rules_count: 2
---

CVE-2026-4558 is a critical vulnerability affecting Linksys MR9600 routers, specifically version 2.0.6.206937. The flaw resides within the `smartConnectConfigure` function of the `SmartConnect.lua` file. Attackers can remotely inject OS commands by manipulating the `configApSsid`, `configApPassphrase`, `srpLogin`, or `srpPassword` arguments. Publicly available exploits exist, increasing the risk of exploitation. The vendor was notified but has not yet provided a patch or response, leaving users…
