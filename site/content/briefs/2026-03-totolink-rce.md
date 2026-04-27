---
title: TOTOLINK X6000R Remote Command Injection Vulnerability
slug: 2026-03-totolink-rce
description: A remote command injection vulnerability exists in TOTOLINK X6000R routers, specifically versions 9.4.0cu.1360_B20241207 and 9.4.0cu.1498_B20250826, allowing attackers to execute arbitrary commands via manipulation of the Hostname argument in the setLanCfg function.
date: "2026-03-24T12:00:00Z"
severities:
  - critical
tags:
  - totolink
  - rce
  - command-injection
  - cve-2026-4611
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4611
  - https://vuldb.com/?ctiid.352475
  - https://vuldb.com/?id.352475
  - https://vuldb.com/?submit.775642
  - https://www.totolink.net/
rules:
  - title: Detect TOTOLINK X6000R Command Injection Attempt
    description: Detects attempts to exploit CVE-2026-4611 by identifying suspicious characters or command injection patterns in the Hostname parameter of requests to /usr/sbin/shttpd
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect TOTOLINK X6000R setLanCfg Access
    description: Detects access to the setLanCfg function in the shttpd webserver.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-4611, affects TOTOLINK X6000R routers running firmware versions 9.4.0cu.1360_B20241207 and 9.4.0cu.1498_B20250826. This vulnerability allows a remote attacker to inject operating system commands by manipulating the Hostname argument passed to the `setLanCfg` function within the `/usr/sbin/shttpd` binary. Successful exploitation grants the attacker the ability to execute arbitrary commands with elevated privileges on the router. Given the widespread deployment…
