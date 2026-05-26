---
title: Totolink A8000RU OS Command Injection (CVE-2026-9387)
slug: 2026-05-totolink-rce
description: CVE-2026-9387 is an OS command injection vulnerability in Totolink A8000RU version 7.1cu.643_b20200521, allowing remote attackers to execute arbitrary commands by manipulating the resetFlags argument in the setUpgradeFW function.
date: "2026-05-26T13:57:04Z"
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
  - A8000RU 7.1cu.643_b20200521
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-9387
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9387
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_334/README.md
  - https://vuldb.com/submit/813433
  - https://vuldb.com/vuln/365350
  - https://vuldb.com/vuln/365350/cti
  - https://www.totolink.net/
rules:
  - title: Detect CVE-2026-9387 Exploitation via Crafted HTTP Request
    description: Detects CVE-2026-9387 exploitation — Monitors HTTP requests to /cgi-bin/cstecgi.cgi with command injection attempts in the resetFlags parameter
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect CVE-2026-9387 Exploitation Attempt via POST Request
    description: Detects CVE-2026-9387 exploitation — Monitors HTTP POST requests to /cgi-bin/cstecgi.cgi with suspicious characters in the resetFlags parameter
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

A security flaw, CVE-2026-9387, was discovered in Totolink A8000RU router firmware version 7.1cu.643_b20200521. This vulnerability resides within the Web Management Interface, specifically in the `/cgi-bin/cstecgi.cgi` file and the `setUpgradeFW` function. Successful exploitation enables remote attackers to inject and execute arbitrary operating system commands. The vulnerability is triggered through manipulation of the `resetFlags` argument. Publicly available exploit code exists, increasing the risk of exploitation. This poses a significant threat to exposed Totolink A8000RU devices, potentially leading to complete compromise of the device and the network it serves.

## Attack Chain

1.  The attacker identifies a vulnerable Totolink A8000RU device running firmware version 7.1cu.643_b20200521.
2.  The attacker sends a crafted HTTP request to the `/cgi-bin/cstecgi.cgi` endpoint.
3.  The request targets the `setUpgradeFW` function.
4.  The attacker manipulates the `resetFlags` argument within the HTTP request.
5.  The manipulated `resetFlags` argument contains OS command injection payloads.
6.  The `setUpgradeFW` function processes the malicious `resetFlags` argument without proper sanitization.
7.  The injected OS commands are executed with elevated privileges on the router's operating system.
8.  The attacker gains remote code execution, allowing them to control the device, potentially leading to further network compromise or data exfiltration.

## Impact

Successful exploitation of CVE-2026-9387 allows a remote, unauthenticated attacker to execute arbitrary commands on the affected Totolink A8000RU device. This could lead to complete device compromise, allowing the attacker to modify router settings, intercept network traffic, or use the device as a pivot point for further attacks within the network. The vulnerability has a CVSS v3.1 score of 9.8, indicating a critical severity. Given the availability of public exploits, vulnerable devices are at immediate risk.

## Recommendation

*   Apply available patches or firmware updates released by Totolink to address CVE-2026-9387.
*   Deploy the Sigma rule `Detect CVE-2026-9387 Exploitation via Crafted HTTP Request` to identify exploitation attempts in web server logs.
*   Monitor web server logs for requests to `/cgi-bin/cstecgi.cgi` with suspicious characters or command injection attempts in the `resetFlags` parameter.
*   Implement network segmentation to limit the potential impact of a compromised router on other network segments.
*   Consider placing routers behind a firewall and restricting access to the management interface from the public internet.
