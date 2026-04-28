---
title: Totolink A7100RU OS Command Injection Vulnerability (CVE-2026-6115)
slug: 2026-04-totolink-cmd-injection
description: A remote attacker can exploit CVE-2026-6115 in Totolink A7100RU version 7.4cu.2313_b20191024 to inject OS commands by manipulating the 'enable' argument of the setAppCfg function in /cgi-bin/cstecgi.cgi, potentially leading to full system compromise.
date: "2026-04-12T05:16:00Z"
severities:
  - critical
tags:
  - cve-2026-6115
  - totolink
  - command injection
  - router
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-6115
    cvss: 9.8
    epss: 0.01254
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6115
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_180/README.md
  - https://vuldb.com/vuln/356975
rules:
  - title: Detect OS Command Injection Attempt via cstecgi.cgi
    description: Detects potential OS command injection attempts targeting the cstecgi.cgi endpoint by looking for shell command syntax.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect cstecgi.cgi access with suspicious User-Agent
    description: Detects access to cstecgi.cgi with unusual User-Agent strings, potentially indicating automated exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-6115 is a critical OS command injection vulnerability affecting Totolink A7100RU routers running firmware version 7.4cu.2313_b20191024. The vulnerability resides in the `setAppCfg` function within the `/cgi-bin/cstecgi.cgi` CGI handler. An unauthenticated, remote attacker can exploit this vulnerability by crafting a malicious request that injects OS commands into the `enable` argument. This allows the attacker to execute arbitrary commands on the underlying operating system of the router, potentially leading to complete system compromise, data exfiltration, or use of the device in botnet activities. The existence of a published exploit increases the risk of widespread exploitation.

## Attack Chain

1.  The attacker identifies a vulnerable Totolink A7100RU router running firmware 7.4cu.2313_b20191024.
2.  The attacker sends a crafted HTTP POST request to `/cgi-bin/cstecgi.cgi`.
3.  The POST request includes the `setAppCfg` function call with a malicious `enable` argument containing an OS command injection payload.
4.  The web server processes the request and passes the attacker-controlled `enable` argument to the `setAppCfg` function without proper sanitization.
5.  The `setAppCfg` function executes the injected OS command using `system()` or a similar function.
6.  The injected command executes with the privileges of the web server process.
7.  The attacker gains arbitrary code execution on the router's operating system.
8.  The attacker can then install malware, change router settings, or use the compromised device for further attacks.

## Impact

Successful exploitation of CVE-2026-6115 allows a remote attacker to execute arbitrary code on the targeted Totolink A7100RU router. This can lead to complete compromise of the device, potentially enabling data theft, modification of router configurations, or the use of the device as part of a botnet. Given the ease of exploitation and the availability of public exploits, a large number of devices could be compromised if left unpatched.

## Recommendation

*   Apply any available firmware updates from Totolink to patch CVE-2026-6115.
*   Monitor web server logs for suspicious POST requests to `/cgi-bin/cstecgi.cgi` with unusual parameters in the query string, using the provided Sigma rule to detect potential exploitation attempts.
*   Implement network segmentation to limit the impact of a compromised router.
*   Deploy the Sigma rule that detects shell commands in cstecgi.cgi requests to your SIEM and tune for your environment.
