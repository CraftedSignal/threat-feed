---
title: Wavlink WL-WN530H4 OS Command Injection Vulnerability
slug: 2026-04-wavlink-command-injection
description: A remote command injection vulnerability exists in the Wavlink WL-WN530H4 router, specifically in the `strcat/snprintf` function of the `/cgi-bin/internet.cgi` file, allowing attackers to execute arbitrary OS commands.
date: "2026-04-17T11:16:11Z"
severities:
  - high
tags:
  - command-injection
  - router
  - cve-2026-6483
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
cves:
  - id: CVE-2026-6483
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6483
  - https://vuldb.com/vuln/358021
rules:
  - title: Detect Wavlink Command Injection Attempt
    description: Detects suspicious requests to /cgi-bin/internet.cgi indicative of command injection attempts in Wavlink routers.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1202
    data_sources:
      - webserver
      - linux
  - title: Detect Wavlink Internet.cgi POST Request
    description: Detects POST requests to /cgi-bin/internet.cgi which might indicate command injection attempts in Wavlink routers.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1202
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical OS command injection vulnerability, tracked as CVE-2026-6483, has been identified in Wavlink WL-WN530H4 routers running firmware version 20220721. The flaw resides within the `/cgi-bin/internet.cgi` file, specifically affecting the `strcat/snprintf` function. Successful exploitation enables remote attackers to execute arbitrary OS commands on the affected device.  The vulnerability is triggered by manipulating input to the vulnerable function. A public exploit is available…
