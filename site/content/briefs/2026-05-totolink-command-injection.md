---
title: Totolink A8000RU OS Command Injection via Web Management Interface (CVE-2026-9404)
slug: 2026-05-totolink-command-injection
description: CVE-2026-9404 is an OS command injection vulnerability in the setDdnsCfg function of the Totolink A8000RU version 7.1cu.643_b20200521 Web Management Interface, allowing remote attackers to execute arbitrary commands by manipulating the 'provider' argument.
date: "2026-05-26T13:57:54Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - cve
  - command injection
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
  - id: CVE-2026-9404
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9404
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_336/README.md
  - https://vuldb.com/submit/813439
  - https://vuldb.com/vuln/365385
  - https://vuldb.com/vuln/365385/cti
  - https://www.totolink.net/
rules:
  - title: Detect CVE-2026-9404 Exploitation - Totolink Command Injection
    description: Detects CVE-2026-9404 exploitation - Attempts to exploit the Totolink A8000RU command injection vulnerability by detecting shell metacharacters in the provider argument of the setDdnsCfg function.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect CVE-2026-9404 Exploitation - Totolink Command Injection Response Code
    description: Detects CVE-2026-9404 exploitation - Monitors for 200 response code after attempting exploitation of command injection vulnerability.
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

A critical vulnerability, CVE-2026-9404, affects Totolink A8000RU router firmware version 7.1cu.643_b20200521. The vulnerability resides in the `setDdnsCfg` function within the `/cgi-bin/cstecgi.cgi` file, part of the Web Management Interface. By manipulating the `provider` argument, a remote attacker can inject and execute arbitrary operating system commands on the underlying system. The vulnerability is remotely exploitable without authentication and has a publicly available exploit. This allows unauthenticated attackers to gain full control of the device.

## Attack Chain

1.  The attacker identifies a vulnerable Totolink A8000RU router running firmware version 7.1cu.643_b20200521.
2.  The attacker sends a crafted HTTP request to `/cgi-bin/cstecgi.cgi`, targeting the `setDdnsCfg` function.
3.  The HTTP request includes a malicious payload within the `provider` argument designed for OS command injection.
4.  The `setDdnsCfg` function fails to properly sanitize the `provider` argument.
5.  The unsanitized input is passed to a system call.
6.  The injected OS command executes with the privileges of the web server.
7.  The attacker establishes a reverse shell or modifies router configuration.
8.  The attacker gains complete control over the compromised device.

## Impact

Successful exploitation of CVE-2026-9404 allows an unauthenticated remote attacker to execute arbitrary commands on the affected Totolink A8000RU device. This can lead to complete system compromise, including modification of device configuration, installation of malware, and potential use of the device as part of a botnet. Given the wide usage of home routers, a successful widespread exploitation could affect thousands of devices, leading to significant disruption and security breaches.

## Recommendation

*   Apply any available patches or firmware updates provided by Totolink to address CVE-2026-9404.
*   Monitor web server logs for suspicious POST requests to `/cgi-bin/cstecgi.cgi` with shell metacharacters in the `provider` argument, as covered by the Sigma rule "Detect CVE-2026-9404 Exploitation - Totolink Command Injection".
*   Implement network intrusion detection system (IDS) rules to detect attempts to exploit CVE-2026-9404 based on the attack chain described above.
*   Place routers behind firewalls and restrict access to management interfaces from the public internet to limit exposure.
