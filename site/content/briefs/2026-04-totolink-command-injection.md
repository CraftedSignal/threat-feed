---
title: Totolink A8000RU OS Command Injection Vulnerability (CVE-2026-7155)
slug: 2026-04-totolink-command-injection
description: CVE-2026-7155 is a critical OS command injection vulnerability in the Totolink A8000RU router that allows remote attackers to execute arbitrary commands by manipulating the 'admpass' argument in the setLoginPasswordCfg function.
date: "2026-04-27T21:16:43Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - cve-2026-7155
  - command-injection
  - totolink
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
  - id: CVE-2026-7155
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7155
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_319/README.md
  - https://vuldb.com/vuln/359754
rules:
  - title: Detect Totolink A8000RU Command Injection Attempt
    description: Detects attempts to exploit the command injection vulnerability (CVE-2026-7155) in Totolink A8000RU via suspicious POST requests to cstecgi.cgi
    platform: sigma
    severity: critical
    tactics:
      - execution
      - mitre_cve_2026_7155
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink A8000RU setLoginPasswordCfg Command Injection
    description: Detects potential exploitation of CVE-2026-7155 by looking for suspicious characters or commands within the 'admpass' parameter in requests to 'cstecgi.cgi'.
    platform: sigma
    severity: high
    tactics:
      - execution
      - mitre_cve_2026_7155
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, identified as CVE-2026-7155, affects the Totolink A8000RU router, specifically version 7.1cu.643_b20200521. This vulnerability resides within the CGI Handler component, in the `setLoginPasswordCfg` function of the `/cgi-bin/cstecgi.cgi` file. By manipulating the `admpass` argument, a remote attacker can inject arbitrary operating system commands. The vulnerability is remotely exploitable without authentication. Given the availability of a public exploit, this poses a significant risk to unpatched devices, potentially leading to full system compromise. Defenders should prioritize patching or mitigating this vulnerability to prevent unauthorized access and control of affected devices.

## Attack Chain

1.  The attacker identifies a vulnerable Totolink A8000RU router running firmware version 7.1cu.643_b20200521.
2.  The attacker sends a crafted HTTP POST request to `/cgi-bin/cstecgi.cgi`, targeting the `setLoginPasswordCfg` function.
3.  The POST request includes the `admpass` argument containing a malicious payload designed for OS command injection.
4.  The `setLoginPasswordCfg` function processes the `admpass` argument without proper sanitization.
5.  The injected OS command is executed by the underlying operating system with the privileges of the web server.
6.  The attacker gains arbitrary code execution on the router.
7.  The attacker pivots to other internal systems.

## Impact

Successful exploitation of CVE-2026-7155 allows a remote attacker to execute arbitrary commands on the affected Totolink A8000RU device. This can lead to complete compromise of the router, including modification of settings, interception of network traffic, or the use of the router as a botnet node. Given the prevalence of these devices in home and small business networks, a large number of devices are potentially vulnerable. The high CVSS score of 9.8 reflects the severity and ease of exploitation.

## Recommendation

*   Deploy the Sigma rule `Detect Totolink A8000RU Command Injection Attempt` to detect exploitation attempts against this vulnerability by monitoring web server logs.
*   Apply available patches or firmware updates provided by Totolink for A8000RU 7.1cu.643_b20200521 to remediate CVE-2026-7155, if available.
*   Monitor network traffic for suspicious outbound connections originating from Totolink A8000RU devices, potentially indicating successful exploitation.
