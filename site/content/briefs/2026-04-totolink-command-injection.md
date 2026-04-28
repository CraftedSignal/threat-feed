---
title: Totolink A8000RU Command Injection Vulnerability (CVE-2026-7243)
slug: 2026-04-totolink-command-injection
description: A command injection vulnerability (CVE-2026-7243) exists in the Totolink A8000RU version 7.1cu.643_b20200521, allowing remote attackers to execute arbitrary OS commands via the setRadvdCfg function in /cgi-bin/cstecgi.cgi by manipulating the maxRtrAdvInterval argument.
date: "2026-04-28T09:16:17Z"
severities:
  - critical
tags:
  - command-injection
  - cve-2026-7243
  - router
  - network
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
  - id: CVE-2026-7243
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7243
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_327/README.md
  - https://vuldb.com/vuln/359850
rules:
  - title: Detect Totolink Command Injection Attempt
    description: Detects potential command injection attempts targeting the Totolink A8000RU router via the setRadvdCfg function by monitoring requests to cstecgi.cgi with suspicious patterns in the maxRtrAdvInterval parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink CGI Access with Suspicious User Agent
    description: Detects access to Totolink CGI endpoints with unusual User-Agent headers, potentially indicating automated exploitation attempts.
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

A command injection vulnerability, identified as CVE-2026-7243, has been discovered in Totolink A8000RU router version 7.1cu.643_b20200521. The vulnerability resides within the CGI Handler component, specifically in the `setRadvdCfg` function of the `/cgi-bin/cstecgi.cgi` file. By manipulating the `maxRtrAdvInterval` argument, an attacker can inject and execute arbitrary operating system commands. The vulnerability is remotely exploitable without authentication, posing a significant risk to affected devices. Publicly available exploits exist, increasing the likelihood of exploitation. This vulnerability allows unauthenticated remote attackers to execute arbitrary commands on the router, potentially leading to full system compromise.

## Attack Chain

1. The attacker sends a crafted HTTP request to the `/cgi-bin/cstecgi.cgi` endpoint.
2. The request targets the `setRadvdCfg` function.
3. The attacker manipulates the `maxRtrAdvInterval` argument within the HTTP request to include malicious OS commands.
4. The CGI Handler processes the request without proper sanitization of the `maxRtrAdvInterval` argument.
5. The `setRadvdCfg` function executes the injected OS commands due to insufficient input validation.
6. The attacker gains arbitrary code execution on the underlying operating system of the Totolink A8000RU router.
7. The attacker can then use the compromised router as a foothold for further network attacks, data exfiltration, or denial of service.

## Impact

Successful exploitation of CVE-2026-7243 allows a remote, unauthenticated attacker to execute arbitrary commands on the affected Totolink A8000RU router. This could lead to complete compromise of the device, allowing the attacker to modify router configurations, intercept network traffic, or use the router as a launchpad for attacks against other devices on the network. Given the widespread use of Totolink routers, a large number of devices are potentially vulnerable, which might lead to botnet recruitment.

## Recommendation

*   Apply available patches or firmware updates provided by Totolink to address CVE-2026-7243.
*   Deploy the Sigma rule `Detect Totolink Command Injection Attempt` to identify exploitation attempts targeting the vulnerable endpoint.
*   Monitor web server logs for suspicious requests to `/cgi-bin/cstecgi.cgi` containing unusual characters or command sequences within the `maxRtrAdvInterval` parameter to detect CVE-2026-7243 exploitation.
