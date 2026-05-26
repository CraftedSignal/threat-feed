---
title: Totolink A8000RU Command Injection Vulnerability (CVE-2026-9408)
slug: 2026-05-totolink-a8000ru-command-injection
description: Totolink A8000RU version 7.1cu.643_b20200521 is vulnerable to command injection via the setStaticDhcpRules function in the /cgi-bin/cstecgi.cgi file, allowing remote attackers to execute arbitrary OS commands by manipulating the 'enable' argument, and a public exploit is available.
date: "2026-05-26T13:59:09Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - command injection
  - router
  - network device
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
  - id: CVE-2026-9408
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9408
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_340/README.md
  - https://vuldb.com/submit/813443
  - https://vuldb.com/vuln/365389
  - https://vuldb.com/vuln/365389/cti
  - https://www.totolink.net/
rules:
  - title: Detect CVE-2026-9408 Exploitation Attempt
    description: Detects CVE-2026-9408 exploitation attempt - Suspicious POST requests to /cgi-bin/cstecgi.cgi with shell metacharacters in the enable parameter
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect CVE-2026-9408 - Suspicious User Agent
    description: Detects CVE-2026-9408 exploitation attempt - unusual User-Agent strings observed during exploitation
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-9408 - Webserver Spawning Shell
    description: Detects CVE-2026-9408 exploitation - Web server process spawning a shell command interpreter
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

A command injection vulnerability, identified as CVE-2026-9408, affects Totolink A8000RU router version 7.1cu.643_b20200521. The vulnerability lies within the `setStaticDhcpRules` function of the `/cgi-bin/cstecgi.cgi` file, specifically within the Web Management Interface component. By manipulating the `enable` argument, a remote attacker can inject and execute arbitrary OS commands on the affected device. This vulnerability poses a significant risk, as it allows complete control of the router. A public exploit is available, increasing the likelihood of exploitation.

## Attack Chain

1. The attacker identifies a vulnerable Totolink A8000RU router running firmware version 7.1cu.643_b20200521.
2. The attacker sends a crafted HTTP request to `/cgi-bin/cstecgi.cgi` targeting the `setStaticDhcpRules` function.
3. The malicious HTTP request includes the `enable` argument with an injected OS command.
4. The Web Management Interface processes the request without proper sanitization of the `enable` argument.
5. The injected OS command is executed with the privileges of the web server process.
6. The attacker gains unauthorized access and control over the device.
7. The attacker could potentially modify router settings, intercept network traffic, or use the compromised device as part of a botnet.

## Impact

Successful exploitation of CVE-2026-9408 allows an attacker to execute arbitrary commands on the affected Totolink A8000RU router. The vulnerable device could be fully compromised, allowing attackers to intercept user data, modify DNS settings, inject malicious scripts into web pages, or use the device as part of a botnet for DDoS attacks. Given the availability of a public exploit, a large number of routers could be at risk of compromise.

## Recommendation

*   Monitor web server logs for suspicious POST requests to `/cgi-bin/cstecgi.cgi` containing shell metacharacters in the `enable` parameter to detect potential exploitation attempts (see Sigma rule `Detect CVE-2026-9408 Exploitation Attempt`).
*   Apply rate limiting to the `/cgi-bin/cstecgi.cgi` endpoint to reduce the impact of brute-force exploitation attempts.
*   Use network intrusion detection systems (IDS) to identify and block malicious traffic targeting the vulnerable endpoint.
*   Inspect traffic for User-Agent strings associated with exploitation tools or unusual patterns accessing `/cgi-bin/cstecgi.cgi` (see Sigma rule `Detect CVE-2026-9408 - Suspicious User Agent`).
*   Monitor process creation events for unexpected processes spawned by the webserver process, especially those involving command interpreters like `sh` or `bash` (see Sigma rule `Detect CVE-2026-9408 - Webserver Spawning Shell`).
