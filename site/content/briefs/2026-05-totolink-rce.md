---
title: Totolink N300RH Command Injection Vulnerability (CVE-2026-9543)
slug: 2026-05-totolink-rce
description: Totolink N300RH version 6.1c.1353_B20190305 is vulnerable to remote command injection via manipulation of the 'admpass' argument in the setPasswordCfg function of the /cgi-bin/cstecgi.cgi file within the Web Management Interface, allowing for remote code execution.
date: "2026-05-26T14:20:53Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - command injection
  - rce
  - totolink
vendors:
  - Totolink
products:
  - N300RH 6.1c.1353_B20190305
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-9543
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9543
  - https://github.com/A1ester/TOTOLINK-N300RH-Command-Injection
  - https://vuldb.com/submit/815068
  - https://vuldb.com/vuln/365607
  - https://vuldb.com/vuln/365607/cti
  - https://www.totolink.net/
rules:
  - title: Detect CVE-2026-9543 Exploitation -- Command Injection in Totolink N300RH
    description: Detects CVE-2026-9543 exploitation -- Attempts to exploit command injection vulnerability in Totolink N300RH via requests to /cgi-bin/cstecgi.cgi
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect CVE-2026-9543 Exploitation -- Shell Metacharacters in admpass Parameter
    description: Detects CVE-2026-9543 exploitation -- HTTP requests with shell metacharacters in the admpass parameter, indicative of command injection attempts.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
rules_count: 2
---

A critical vulnerability, CVE-2026-9543, has been identified in Totolink N300RH router firmware version 6.1c.1353_B20190305. The vulnerability resides within the Web Management Interface, specifically in the `/cgi-bin/cstecgi.cgi` file's `setPasswordCfg` function. By manipulating the `admpass` argument, a remote attacker can inject arbitrary operating system commands. Publicly available exploit code exists, increasing the risk of exploitation. This vulnerability allows unauthenticated attackers to execute commands on the underlying operating system of the router.

## Attack Chain

1.  An unauthenticated attacker identifies a vulnerable Totolink N300RH router running firmware version 6.1c.1353_B20190305.
2.  The attacker crafts a malicious HTTP request targeting the `/cgi-bin/cstecgi.cgi` endpoint.
3.  Within the HTTP request, the attacker manipulates the `admpass` argument in the `setPasswordCfg` function to include OS command injection payloads.
4.  The web server processes the request and passes the `admpass` argument to the underlying system.
5.  The injected OS commands are executed with the privileges of the web server process.
6.  The attacker can then execute commands to gain shell access, modify router configurations, or install malware.
7.  The attacker uses the gained access to pivot to other devices on the network or to maintain persistence on the router.

## Impact

Successful exploitation of CVE-2026-9543 allows an unauthenticated remote attacker to execute arbitrary operating system commands on the affected Totolink N300RH device. This can lead to complete compromise of the device, potentially enabling attackers to eavesdrop on network traffic, modify router settings, or use the device as a point of entry for further attacks on the internal network. Given the high CVSS score (9.8), this vulnerability poses a significant risk.

## Recommendation

*   Deploy the Sigma rule to detect command injection attempts targeting the `/cgi-bin/cstecgi.cgi` endpoint (see rule `Detect CVE-2026-9543 Exploitation -- Command Injection in Totolink N300RH`).
*   Monitor web server logs for requests containing shell metacharacters in the `admpass` parameter (see rule `Detect CVE-2026-9543 Exploitation -- Shell Metacharacters in admpass Parameter`).
*   Apply any available firmware updates released by Totolink to address this vulnerability.
*   If firmware updates are not available, consider disabling remote access to the router's web management interface or implementing access control lists to restrict access to trusted IP addresses.
