---
title: Totolink NR1800X Command Injection Vulnerability
slug: 2026-05-totolink-command-injection
description: A command injection vulnerability exists in Totolink NR1800X version 9.1.0u.6279_B20210910, affecting the function sub_41A68C of the file /cgi-bin/cstecgi.cgi; by manipulating the argument setUssd, a remote attacker can inject commands, and an exploit is publicly available.
date: "2026-05-01T03:16:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - router
  - network
vendors:
  - Totolink
products:
  - NR1800X 9.1.0u.6279_B20210910
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7548
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7548
  - https://github.com/newym/cve/blob/main/totolink%20nr1800x%20command%20injection.md
  - https://vuldb.com/vuln/360358
rules:
  - title: Detect Totolink NR1800X Command Injection Attempt
    description: Detects command injection attempts in the setUssd parameter of the /cgi-bin/cstecgi.cgi endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1550
    data_sources:
      - webserver
      - linux
  - title: Detect suspicious characters in URI query
    description: Detects the presence of suspicious characters indicative of command injection attempts within URI queries.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A command injection vulnerability, identified as CVE-2026-7548, affects Totolink NR1800X router version 9.1.0u.6279_B20210910. The vulnerability resides within the `sub_41A68C` function of the `/cgi-bin/cstecgi.cgi` file. By manipulating the `setUssd` argument, a remote attacker can inject arbitrary commands into the system. Publicly available exploit code makes exploitation easier. This vulnerability poses a significant risk as it allows unauthenticated remote attackers to execute arbitrary commands on the affected device, potentially leading to full system compromise.

## Attack Chain

1.  The attacker identifies a vulnerable Totolink NR1800X device running firmware version 9.1.0u.6279_B20210910.
2.  The attacker sends a crafted HTTP request to the `/cgi-bin/cstecgi.cgi` endpoint.
3.  The HTTP request includes the `setUssd` argument with a malicious payload designed to inject a command.
4.  The `sub_41A68C` function processes the `setUssd` argument without proper sanitization.
5.  The injected command is executed by the system with the privileges of the web server process.
6.  The attacker gains initial access and can execute arbitrary commands on the device.
7.  The attacker may then use the command execution to escalate privileges, install malware, or pivot to other devices on the network.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the affected Totolink NR1800X router. This could lead to complete compromise of the device, allowing the attacker to control network traffic, modify router settings, or use the router as a pivot point to attack other devices on the network. Given the wide usage of Totolink routers, a large number of devices could be vulnerable.

## Recommendation

*   Monitor web server logs for requests to `/cgi-bin/cstecgi.cgi` containing suspicious characters or command injection attempts in the `setUssd` parameter, using the Sigma rule provided below.
*   Implement rate limiting on the `/cgi-bin/cstecgi.cgi` endpoint to mitigate brute-force exploitation attempts.
*   Apply available patches provided by Totolink to address the CVE-2026-7548 vulnerability.
*   Deploy the Sigma rule to your SIEM and tune for your environment.
