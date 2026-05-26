---
title: Totolink A8000RU Command Injection Vulnerability (CVE-2026-9475)
slug: 2026-05-totolink-command-injection
description: Totolink A8000RU version 7.1cu.643_b20200521 is vulnerable to remote OS command injection via manipulation of the Comment argument in the setIpQosRules function, allowing unauthenticated attackers to execute arbitrary commands on the device.
date: "2026-05-26T14:04:07Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - command injection
  - router vulnerability
  - CVE-2026-9475
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
  - id: CVE-2026-9475
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9475
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_347/README.md
  - https://vuldb.com/submit/813458
  - https://vuldb.com/vuln/365456
  - https://vuldb.com/vuln/365456/cti
  - https://www.totolink.net/
rules:
  - title: Detect CVE-2026-9475 Exploitation Attempt via Web Logs
    description: Detects CVE-2026-9475 exploitation attempt — HTTP POST requests to cstecgi.cgi with command injection attempt in Comment parameter
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect CVE-2026-9475 Command Injection via Process Creation
    description: Detects CVE-2026-9475 exploitation — Monitors for processes spawned by the web server that execute suspicious commands.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical command injection vulnerability, CVE-2026-9475, affects Totolink A8000RU router version 7.1cu.643_b20200521. The vulnerability lies within the Web Management Interface component, specifically in the `/cgi-bin/cstecgi.cgi` file's `setIpQosRules` function. By manipulating the `Comment` argument, an unauthenticated attacker can inject and execute arbitrary operating system commands on the underlying system. Public exploits are available, increasing the risk of widespread exploitation. Successful exploitation allows for complete system compromise.

## Attack Chain

1. The attacker identifies a vulnerable Totolink A8000RU router running firmware version 7.1cu.643_b20200521.
2. The attacker sends a crafted HTTP request to the `/cgi-bin/cstecgi.cgi` endpoint, targeting the `setIpQosRules` function.
3. The HTTP request includes a malicious payload within the `Comment` argument designed to inject OS commands.
4. The web server processes the request and passes the `Comment` argument to the vulnerable `setIpQosRules` function without proper sanitization.
5. The injected OS commands are executed with the privileges of the web server process.
6. The attacker gains remote code execution on the router.
7. The attacker can then perform actions such as modifying router configurations, installing backdoors, or pivoting to other devices on the network.
8. The attacker achieves complete control over the compromised router.

## Impact

Successful exploitation of CVE-2026-9475 results in complete compromise of the Totolink A8000RU router. An attacker can gain full control of the device, potentially leading to data theft, network disruption, or use of the router as part of a botnet. Given the ease of exploitation and the availability of public exploits, a large number of devices could be targeted, impacting both home and small business networks.

## Recommendation

*   Apply the vendor patch as soon as it becomes available.
*   Monitor web server logs for suspicious POST requests to `/cgi-bin/cstecgi.cgi` with unusual characters in the `Comment` parameter, as detected by the Sigma rule "Detect CVE-2026-9475 Exploitation Attempt via Web Logs".
*   Implement network intrusion detection system (IDS) rules to detect and block exploitation attempts targeting CVE-2026-9475.
*   Disable remote administration access to the router to limit the attack surface.
*   Deploy the Sigma rule "Detect CVE-2026-9475 Command Injection via Process Creation" to identify processes spawned from the web server with injected commands.
