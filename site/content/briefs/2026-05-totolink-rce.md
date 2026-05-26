---
title: Totolink A8000RU OS Command Injection Vulnerability (CVE-2026-9406)
slug: 2026-05-totolink-rce
description: A vulnerability in Totolink A8000RU version 7.1cu.643_b20200521 allows an attacker to perform OS command injection through manipulation of the 'enable' argument in the setRemoteCfg function within the Web Management Interface component's /cgi-bin/cstecgi.cgi file; the attack can be executed remotely and the exploit is publicly available.
date: "2026-05-26T13:58:29Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command injection
  - router
  - cve-2026-9406
vendors:
  - Totolink
products:
  - A8000RU 7.1cu.643_b20200521
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-9406
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9406
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_338/README.md
  - https://vuldb.com/submit/813441
  - https://vuldb.com/vuln/365387
  - https://vuldb.com/vuln/365387/cti
  - https://www.totolink.net/
rules:
  - title: Detects CVE-2026-9406 Exploitation — Totolink A8000RU Command Injection Attempt
    description: Detects CVE-2026-9406 exploitation attempt — HTTP POST to /cgi-bin/cstecgi.cgi with shell metacharacters in the enable parameter, indicating command injection.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detects CVE-2026-9406 Exploitation — Totolink A8000RU Suspicious User Agent
    description: Detects CVE-2026-9406 exploitation attempt based on unusual User-Agent headers.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

A command injection vulnerability, CVE-2026-9406, has been identified in the Totolink A8000RU router, specifically version 7.1cu.643_b20200521. This flaw resides within the Web Management Interface and can be exploited by remotely manipulating the 'enable' argument of the setRemoteCfg function in the `/cgi-bin/cstecgi.cgi` file. Publicly available exploit code makes this vulnerability particularly dangerous, as attackers can easily leverage it to execute arbitrary commands on the affected device, leading to complete system compromise. Given the widespread use of these routers, this vulnerability poses a significant risk to both home and business networks.

## Attack Chain

1.  The attacker identifies a vulnerable Totolink A8000RU router with firmware version 7.1cu.643_b20200521.
2.  The attacker crafts a malicious HTTP request targeting the `/cgi-bin/cstecgi.cgi` endpoint.
3.  The request includes the `setRemoteCfg` function call with a manipulated `enable` argument containing OS command injection payloads.
4.  The Web Management Interface processes the request without proper sanitization of the `enable` argument.
5.  The injected OS command is executed by the underlying operating system with the privileges of the web server process.
6.  The attacker gains remote code execution on the router, enabling them to install malware, modify settings, or pivot to other network devices.
7.  The attacker may establish a reverse shell connection to an external server for persistent access.

## Impact

Successful exploitation of CVE-2026-9406 allows unauthenticated attackers to execute arbitrary commands on vulnerable Totolink A8000RU routers. This could lead to complete compromise of the device, including unauthorized access to network traffic, modification of router settings, and the potential use of the router as a botnet node. Given the ease of exploitation, a large number of devices could be affected.

## Recommendation

*   Monitor webserver logs for suspicious POST requests to `/cgi-bin/cstecgi.cgi` with shell metacharacters in the `enable` parameter using the Sigma rule provided below.
*   Apply any available firmware updates from Totolink to patch CVE-2026-9406.
*   Implement network segmentation to limit the potential impact of compromised routers.
*   If updates are unavailable, consider blocking access to the `/cgi-bin/cstecgi.cgi` endpoint from the external network.
