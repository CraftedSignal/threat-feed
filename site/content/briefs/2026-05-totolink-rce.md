---
title: Totolink A8000RU OS Command Injection Vulnerability (CVE-2026-9384)
slug: 2026-05-totolink-rce
description: A remote attacker can inject OS commands by manipulating the 'ip' argument in the setDiagnosisCfg function within the /cgi-bin/cstecgi.cgi file of the Totolink A8000RU version 7.1cu.643_b20200521 Web Management Interface.
date: "2026-05-26T13:56:08Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command injection
  - rce
  - cve-2026-9384
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
  - id: CVE-2026-9384
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9384
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_331/README.md
  - https://vuldb.com/submit/813429
  - https://vuldb.com/vuln/365347
  - https://vuldb.com/vuln/365347/cti
  - https://www.totolink.net/
rules:
  - title: Detect CVE-2026-9384 Exploitation — Totolink Command Injection
    description: Detects CVE-2026-9384 exploitation — HTTP requests to /cgi-bin/cstecgi.cgi with shell metacharacters in the ip parameter indicating a command injection attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect Totolink cstecgi.cgi Access
    description: Detects access to the Totolink cstecgi.cgi file which is often targeted in exploits.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A command injection vulnerability, identified as CVE-2026-9384, affects Totolink A8000RU router version 7.1cu.643_b20200521. The vulnerability resides within the Web Management Interface, specifically in the `setDiagnosisCfg` function of the `/cgi-bin/cstecgi.cgi` file. By manipulating the `ip` argument, an unauthenticated attacker can execute arbitrary operating system commands on the affected device. Public exploits for this vulnerability are available, increasing the risk of exploitation. This vulnerability allows for complete system compromise and control, therefore defenders should apply mitigations immediately.

## Attack Chain

1.  An unauthenticated attacker sends a crafted HTTP request to the `/cgi-bin/cstecgi.cgi` endpoint.
2.  The HTTP request targets the `setDiagnosisCfg` function with a malicious `ip` argument.
3.  The `ip` argument contains OS command injection payloads, such as shell metacharacters (`;`, `|`, `&&`).
4.  The `setDiagnosisCfg` function fails to properly sanitize or validate the `ip` argument.
5.  The unsanitized `ip` argument is passed to a system call, resulting in OS command execution.
6.  The attacker can then execute commands to gain shell access, modify system configurations, or install malware.
7.  The attacker pivots to other devices on the network or exfiltrates sensitive data.
8.  The final objective is complete control over the router and potentially the entire network.

## Impact

Successful exploitation of CVE-2026-9384 allows unauthenticated remote attackers to execute arbitrary commands on the affected Totolink A8000RU routers. This can lead to full device compromise, allowing attackers to modify router settings, intercept network traffic, or use the router as a pivot point for further attacks within the network. Given the availability of public exploits, a wide range of threat actors may target this vulnerability.

## Recommendation

*   Apply vendor-provided patches or firmware updates for Totolink A8000RU version 7.1cu.643_b20200521 to mitigate CVE-2026-9384.
*   Deploy the Sigma rule "Detect CVE-2026-9384 Exploitation — Totolink Command Injection" to identify exploitation attempts in web server logs.
*   Monitor web server logs for suspicious requests to `/cgi-bin/cstecgi.cgi` containing shell metacharacters in the `ip` argument, per the attack chain detailed above.
*   Implement network segmentation to limit the impact of compromised devices on the internal network.
