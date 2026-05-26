---
title: Totolink A8000RU Command Injection Vulnerability (CVE-2026-9476)
slug: 2026-05-totolink-rce
description: Totolink A8000RU version 7.1cu.643_b20200521 is vulnerable to OS command injection via the setPasswordCfg function in /cgi-bin/cstecgi.cgi, allowing remote attackers to execute arbitrary commands by manipulating the admpass argument.
date: "2026-05-26T14:04:26Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - command-injection
  - rce
  - cve
  - router
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
  - id: CVE-2026-9476
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9476
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_348/README.md
  - https://vuldb.com/submit/813459
  - https://vuldb.com/vuln/365457
  - https://vuldb.com/vuln/365457/cti
  - https://www.totolink.net/
rules:
  - title: Detects CVE-2026-9476 Exploitation — Totolink A8000RU Command Injection Attempt
    description: Detects CVE-2026-9476 exploitation — HTTP POST request to /cgi-bin/cstecgi.cgi with shell metacharacters in the admpass parameter indicating command injection attempt
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detects CVE-2026-9476 Exploitation — Totolink A8000RU setPasswordCfg Access
    description: Detects access to the setPasswordCfg function in Totolink A8000RU, which is associated with CVE-2026-9476
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A critical vulnerability, CVE-2026-9476, has been identified in Totolink A8000RU router version 7.1cu.643_b20200521. The vulnerability resides within the Web Management Interface, specifically in the `setPasswordCfg` function of the `/cgi-bin/cstecgi.cgi` file.  A remote attacker can exploit this vulnerability by injecting OS commands through the `admpass` argument.  The exploit is publicly available, increasing the likelihood of exploitation in the wild. Successful exploitation allows for complete control over the affected device.

## Attack Chain

1.  The attacker identifies a Totolink A8000RU router running firmware version 7.1cu.643_b20200521.
2.  The attacker sends a crafted HTTP POST request to `/cgi-bin/cstecgi.cgi`.
3.  The request targets the `setPasswordCfg` function.
4.  The attacker injects an OS command into the `admpass` parameter of the HTTP POST request. This exploits the CWE-78 vulnerability.
5.  The `cstecgi.cgi` script processes the request without proper sanitization of the `admpass` argument.
6.  The injected OS command is executed with the privileges of the web server.
7.  The attacker gains arbitrary code execution on the router's operating system.
8.  The attacker can then use this access to modify router settings, install malware, or pivot to other devices on the network.

## Impact

Successful exploitation of CVE-2026-9476 grants an attacker complete control over the compromised Totolink A8000RU router. This can lead to a variety of malicious outcomes, including the ability to eavesdrop on network traffic, modify DNS settings to redirect users to phishing sites, or use the router as part of a botnet. Given the high CVSS score (9.8) and the public availability of an exploit, this vulnerability poses a significant risk.

## Recommendation

*   Upgrade to a patched version of the Totolink A8000RU firmware that addresses CVE-2026-9476, if available from the vendor.
*   Monitor webserver logs for POST requests to `/cgi-bin/cstecgi.cgi` with shell metacharacters in the `admpass` parameter using the Sigma rule provided below.
*   Implement network intrusion detection system (IDS) rules to detect attempts to exploit this vulnerability by monitoring HTTP traffic to the router's web management interface.
*   Apply strict input validation and sanitization to all user-supplied data in web applications to prevent command injection vulnerabilities.
*   Disable remote access to the router's web management interface if not required.
