---
title: Totolink A8000RU OS Command Injection Vulnerability
slug: 2026-04-totolink-command-injection
description: A critical OS command injection vulnerability (CVE-2026-7153) exists in the Totolink A8000RU router, specifically in the `setMiniuiHomeInfoShow` function, allowing remote attackers to execute arbitrary commands by manipulating the `sys_info` argument.
date: "2026-04-27T20:32:04Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - cve-2026-7153
  - command injection
  - router
vendors:
  - Totolink
products:
  - A8000RU 7.1cu.643_b20200521
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-7153
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7153
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_317/README.md
rules:
  - title: Detect Totolink A8000RU Command Injection Attempt
    description: Detects potential command injection attempts targeting the Totolink A8000RU router via the cstecgi.cgi endpoint by looking for common command injection payloads.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Exploitation of Totolink CVE-2026-7153
    description: Detects successful exploitation of the Totolink A8000RU router vulnerability (CVE-2026-7153) by monitoring for suspicious process creation events following requests to the vulnerable CGI endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical security vulnerability, identified as CVE-2026-7153, has been discovered in the Totolink A8000RU router, version 7.1cu.643_b20200521. This flaw resides within the CGI Handler component, specifically affecting the `setMiniuiHomeInfoShow` function located in the `/cgi-bin/cstecgi.cgi` file. By exploiting this vulnerability, a remote attacker can inject and execute arbitrary operating system commands on the affected device. Public exploits are available, increasing the risk of widespread exploitation. This vulnerability allows unauthenticated remote attackers to gain complete control of the device.

## Attack Chain

1. The attacker identifies a vulnerable Totolink A8000RU router running firmware version 7.1cu.643_b20200521.
2. The attacker crafts a malicious HTTP request targeting the `/cgi-bin/cstecgi.cgi` endpoint.
3. The malicious request includes a manipulated `sys_info` argument designed to inject an OS command into the `setMiniuiHomeInfoShow` function.
4. The CGI Handler processes the request, and the vulnerable `setMiniuiHomeInfoShow` function fails to properly sanitize the `sys_info` argument.
5. The injected OS command is executed with the privileges of the web server process.
6. The attacker leverages the command execution to gain further access to the system, potentially downloading malware or modifying system configurations.
7. The attacker establishes a persistent backdoor for future access.

## Impact

Successful exploitation of this vulnerability allows a remote, unauthenticated attacker to execute arbitrary OS commands on the affected Totolink A8000RU router. This could lead to complete device compromise, including modification of router settings, installation of malicious firmware, interception of network traffic, and potential use of the router as part of a botnet. Given the availability of public exploits, a large number of devices are at risk.

## Recommendation

*   Monitor web server logs for requests to `/cgi-bin/cstecgi.cgi` containing suspicious characters or command injection attempts in the `sys_info` parameter to trigger the rule `Detect Totolink A8000RU Command Injection Attempt`
*   Block or quarantine network traffic to and from devices attempting to access `/cgi-bin/cstecgi.cgi` with potentially malicious payloads.
*   Consider deploying a web application firewall (WAF) rule to block requests matching the attack patterns identified in CVE-2026-7153.
