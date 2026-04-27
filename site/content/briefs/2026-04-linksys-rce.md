---
title: Linksys MR9600 Command Injection Vulnerability (CVE-2026-6992)
slug: 2026-04-linksys-rce
description: CVE-2026-6992 is a command injection vulnerability in the Linksys MR9600 router that allows remote attackers to execute arbitrary OS commands by manipulating the 'pin' argument in the BTRequestGetSmartConnectStatus function.
date: "2026-04-26T12:00:00Z"
severities:
  - critical
tags:
  - cve-2026-6992
  - command-injection
  - router
  - rce
vendors:
  - Linksys
products:
  - MR9600 (2.0.6.206937)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-6992
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6992
  - https://github.com/utmost3/cve/issues/2
  - https://vuldb.com/submit/797086
  - https://vuldb.com/vuln/359544
  - https://vuldb.com/vuln/359544/cti
rules:
  - title: Detect CVE-2026-6992 Exploitation Attempt
    description: Detects attempts to exploit CVE-2026-6992 by looking for requests to the vulnerable script with command injection patterns.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Shell Activity via Web Request
    description: Detects suspicious shell activity in web requests, indicating potential command injection.
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

A command injection vulnerability, CVE-2026-6992, affects the Linksys MR9600 router, specifically version 2.0.6.206937. The vulnerability resides in the JNAP Action Handler component within the `/etc/init.d/run_central2.sh` script. Attackers can remotely exploit this flaw by manipulating the `pin` argument passed to the `BTRequestGetSmartConnectStatus` function. This allows for the execution of arbitrary operating system commands on the affected device. A public exploit is available, increasing…
