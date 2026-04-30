---
title: Totolink A8000RU OS Command Injection Vulnerability
slug: 2026-04-totolink-rce
description: Totolink A8000RU version 7.1cu.643_b20200521 is vulnerable to OS command injection via manipulation of the `wifiOff` argument in the `setWiFiBasicCfg` function of the `/cgi-bin/cstecgi.cgi` CGI handler, allowing a remote attacker to execute arbitrary commands on the system.
date: "2026-04-28T09:17:41Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2026-7241
  - command-injection
  - router
vendors:
  - Totolink
products:
  - A8000RU
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7241
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7241
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_325/README.md
  - https://vuldb.com/vuln/359848
rules:
  - title: Detect Totolink A8000RU Command Injection Attempt
    description: Detects potential command injection attempts targeting the Totolink A8000RU vulnerability (CVE-2026-7241) by monitoring requests to the vulnerable CGI endpoint with suspicious command injection patterns in the wifiOff parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious CGI Request Arguments
    description: This rule detects suspicious characters commonly used in command injection attempts within CGI request arguments, focusing on detecting potential exploitation attempts.
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

A critical vulnerability, CVE-2026-7241, has been identified in Totolink A8000RU router firmware version 7.1cu.643_b20200521. This vulnerability resides within the CGI Handler component, specifically in the `setWiFiBasicCfg` function of the `/cgi-bin/cstecgi.cgi` file. Successful exploitation allows a remote attacker to inject and execute arbitrary operating system commands by manipulating the `wifiOff` argument. The vulnerability has been publicly disclosed, increasing the risk of exploitation. This poses a significant threat to users of the affected router model, potentially leading to complete system compromise.

## Attack Chain

1. The attacker identifies a Totolink A8000RU router running firmware version 7.1cu.643_b20200521.
2. The attacker sends a crafted HTTP request to the `/cgi-bin/cstecgi.cgi` endpoint.
3. The HTTP request targets the `setWiFiBasicCfg` function.
4. The attacker injects malicious OS commands into the `wifiOff` argument of the HTTP request.
5. The CGI handler processes the request without proper sanitization of the `wifiOff` argument.
6. The injected OS commands are executed by the system with the privileges of the web server.
7. The attacker gains remote shell access or performs other malicious actions, such as modifying router settings.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary operating system commands on the affected Totolink A8000RU router. This can lead to complete compromise of the device, potentially enabling the attacker to eavesdrop on network traffic, modify router configuration, or use the router as a node in a botnet. Given the widespread use of Totolink routers, a successful attack could impact numerous home and small business networks.

## Recommendation

*   Deploy the Sigma rule "Detect Totolink A8000RU Command Injection Attempt" to your SIEM to identify exploitation attempts targeting the vulnerable endpoint.
*   Apply the Sigma rule "Detect Suspicious CGI Request Arguments" to identify unusual commands in cgi requests.
*   Monitor web server logs for requests to `/cgi-bin/cstecgi.cgi` with suspicious characters or commands in the `wifiOff` parameter, as this is the attack vector described in CVE-2026-7241.
