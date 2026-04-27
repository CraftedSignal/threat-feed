---
title: Tenda HG3 Router Command Injection Vulnerability (CVE-2026-7096)
slug: 2024-01-tenda-hg3-command-injection
description: A command injection vulnerability (CVE-2026-7096) exists in the Tenda HG3 2.0 300003070 router, allowing remote attackers to execute arbitrary OS commands by manipulating the 'fmgpon_loid' argument in the 'formgponConf' function of the '/boaform/admin/formgponConf' file due to insufficient input validation.
date: "2024-01-03T12:00:00Z"
severities:
  - critical
tags:
  - command-injection
  - router
  - tenda
vendors:
  - Tenda
products:
  - HG3 2.0 300003070
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7096
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7096
rules:
  - title: Detect Tenda HG3 Command Injection Attempt
    description: Detects potential command injection attempts targeting the Tenda HG3 router by monitoring HTTP POST requests to the 'formgponConf' endpoint with suspicious command-like strings in the 'fmgpon_loid' parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda HG3 Configuration File Access
    description: Detects access to the Tenda HG3 configuration file, which may indicate an attempt to exploit the command injection vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical command injection vulnerability, identified as CVE-2026-7096, affects Tenda HG3 2.0 300003070 routers. The vulnerability resides in the 'formgponConf' function within the '/boaform/admin/formgponConf' file. An attacker can exploit this flaw by manipulating the 'fmgpon_loid' argument. Successful exploitation allows a remote attacker to execute arbitrary operating system commands on the affected device. Given the public availability of an exploit, Tenda HG3 devices are at immediate…
