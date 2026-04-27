---
title: Totolink A7100RU OS Command Injection Vulnerability (CVE-2026-6154)
slug: 2026-04-totolink-command-injection
description: CVE-2026-6154 is a critical vulnerability in Totolink A7100RU firmware that allows remote attackers to inject OS commands by manipulating the 'wizard' argument in the setWizardCfg function, leading to potential system compromise.
date: "2026-04-13T04:16:14Z"
severities:
  - critical
tags:
  - cve-2026-6154
  - command-injection
  - totolink
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6154
    cvss: 9.8
    epss: 0.01254
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6154
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_194/README.md
  - https://vuldb.com/vuln/357034
rules:
  - title: Detect Totolink A7100RU Command Injection Attempt
    description: Detects attempts to exploit the Totolink A7100RU command injection vulnerability (CVE-2026-6154) by looking for suspicious POST requests to the cstecgi.cgi endpoint with shell commands in the wizard argument.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink A7100RU Command Injection Successful
    description: Detects a successful exploitation of the Totolink A7100RU command injection vulnerability (CVE-2026-6154) by looking for evidence of command execution in web server logs after a suspicious POST to the cstecgi.cgi endpoint.
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
rules_count: 2
---

A critical OS command injection vulnerability, CVE-2026-6154, affects Totolink A7100RU devices running firmware version 7.4cu.2313_b20191024. The vulnerability resides in the `setWizardCfg` function within the `/cgi-bin/cstecgi.cgi` CGI handler. By manipulating the `wizard` argument, a remote, unauthenticated attacker can inject and execute arbitrary OS commands on the affected device. Publicly available exploits exist, increasing the risk of widespread exploitation. This vulnerability poses a…
