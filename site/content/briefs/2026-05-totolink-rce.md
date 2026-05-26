---
title: Totolink A8000RU OS Command Injection (CVE-2026-9434)
slug: 2026-05-totolink-rce
description: A remote unauthenticated OS command injection vulnerability (CVE-2026-9434) exists in the setWiFiWpsCfg function of the /cgi-bin/cstecgi.cgi file on Totolink A8000RU version 7.1cu.643_b20200521, allowing for remote code execution.
date: "2026-05-26T14:01:42Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - cve
  - command injection
  - rce
vendors:
  - Totolink
products:
  - A8000RU 7.1cu.643_b20200521
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-9434
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9434
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_355/README.md
  - https://vuldb.com/submit/813907
  - https://vuldb.com/vuln/365415
  - https://vuldb.com/vuln/365415/cti
  - https://www.totolink.net/
rules:
  - title: Detect CVE-2026-9434 Exploitation Attempt
    description: Detects CVE-2026-9434 exploitation attempt - crafted request to cstecgi.cgi with command injection
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect Crafted CGI Request
    description: Detects potentially malicious requests to the /cgi-bin/cstecgi.cgi endpoint
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
rules_count: 2
---

A critical security vulnerability, tracked as CVE-2026-9434, has been identified in the Totolink A8000RU router, specifically version 7.1cu.643_b20200521. The vulnerability resides within the Web Management Interface, affecting the `setWiFiWpsCfg` function in the `/cgi-bin/cstecgi.cgi` file. Successful exploitation allows an unauthenticated attacker to inject arbitrary operating system commands by manipulating the `wscDisabled` argument. This vulnerability is remotely exploitable and has a publicly available exploit, increasing the risk of widespread exploitation. The impact includes complete compromise of the affected device, potentially allowing attackers to pivot to internal networks.

## Attack Chain

1.  The attacker identifies a vulnerable Totolink A8000RU router running firmware version 7.1cu.643_b20200521.
2.  The attacker sends a crafted HTTP request to the `/cgi-bin/cstecgi.cgi` endpoint.
3.  The HTTP request includes a modified `wscDisabled` argument within the `setWiFiWpsCfg` function call.
4.  The modified `wscDisabled` argument contains malicious OS commands.
5.  The `setWiFiWpsCfg` function fails to properly sanitize the `wscDisabled` argument.
6.  The unsanitized input is passed to the underlying operating system for execution.
7.  The injected OS command is executed with the privileges of the web server.
8.  The attacker gains remote code execution on the device, enabling further malicious activities such as data exfiltration or lateral movement.

## Impact

Successful exploitation of CVE-2026-9434 allows an unauthenticated remote attacker to execute arbitrary commands on the affected Totolink A8000RU device. This can lead to complete system compromise, allowing the attacker to control the device, potentially exposing sensitive data, and using the compromised device as a pivot point for further attacks within the network. Given the widespread use of these devices in home and small business networks, the potential impact is significant.

## Recommendation

*   Deploy the Sigma rule `Detect CVE-2026-9434 Exploitation Attempt` to your SIEM to identify exploitation attempts in web server logs.
*   Apply the Sigma rule `Detect Crafted CGI Request` to identify potentially malicious requests to the `/cgi-bin/cstecgi.cgi` endpoint.
*   Monitor web server logs for requests to `/cgi-bin/cstecgi.cgi` with suspicious parameters indicative of command injection attempts, as detected by the `Detect Crafted CGI Request` rule.
