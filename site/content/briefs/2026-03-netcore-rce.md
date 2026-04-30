---
title: Netcore Power 15AX Remote Command Execution Vulnerability
slug: 2026-03-netcore-rce
description: CVE-2026-4840 is a critical command injection vulnerability in the Netcore Power 15AX router that allows remote attackers to execute arbitrary OS commands by manipulating the IpAddr argument in the setTools function of the /bin/netis.cgi file.
date: "2026-03-26T05:16:40Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - command-injection
  - rce
  - vulnerability
  - netcore
  - router
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4840
rules:
  - title: Detect Netis.cgi Command Injection Attempt
    description: Detects attempts to exploit the command injection vulnerability (CVE-2026-4840) in the /bin/netis.cgi endpoint of Netcore Power 15AX routers by identifying suspicious characters or command sequences in the IpAddr parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Netis.cgi Access from Uncommon IPs
    description: Detects access to /bin/netis.cgi from IP addresses not typically seen accessing the router's web interface, which could indicate unauthorized access or exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A remote command execution vulnerability, CVE-2026-4840, affects Netcore Power 15AX devices with firmware versions up to 3.0.0.6938. The vulnerability resides in the Diagnostic Tool Interface, specifically within the `setTools` function of the `/bin/netis.cgi` file. By manipulating the `IpAddr` argument, an attacker can inject and execute arbitrary operating system commands on the device. This vulnerability poses a significant risk, as it allows unauthenticated remote attackers to gain complete…
