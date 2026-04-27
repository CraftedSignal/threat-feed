---
title: Totolink N300RH OS Command Injection Vulnerability (CVE-2026-6158)
slug: 2026-04-totolink-rce
description: A remote OS command injection vulnerability exists in Totolink N300RH firmware version 6.1c.1353_B20190305 due to improper handling of the FileName argument in the setUpgradeUboot function, potentially allowing attackers to execute arbitrary commands.
date: "2026-04-13T05:17:44Z"
severities:
  - critical
tags:
  - cve
  - cve-2026-6158
  - command-injection
  - totolink
  - rce
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-6158
    cvss: 7.3
    epss: 0.04857
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6158
  - https://github.com/xyh4ck/iot_poc/tree/main/TOTOLINK/N300RHv4/02_setUpgradeUboot_RCE
  - https://vuldb.com/vuln/357038
rules:
  - title: Detect Totolink N300RH setUpgradeUboot Command Injection Attempt
    description: Detects potential command injection attempts in HTTP requests targeting the setUpgradeUboot function in Totolink N300RH devices.
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
  - title: Detect Multiple OS Command Injection Characters in URI Query
    description: Detects multiple OS command injection characters within a URI query string, indicative of a command injection attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-6158 describes an OS command injection vulnerability affecting Totolink N300RH devices running firmware version 6.1c.1353_B20190305. The vulnerability lies within the `setUpgradeUboot` function of the `upgrade.so` file. By manipulating the `FileName` argument, a remote attacker can inject and execute arbitrary OS commands on the underlying system. Publicly available exploits exist, increasing the risk of exploitation. This vulnerability allows for complete compromise of the affected…
