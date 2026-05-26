---
title: Totolink A8000RU OS Command Injection via Web Management Interface (CVE-2026-9478)
slug: 2026-05-totolink-rce
description: CVE-2026-9478 is an OS command injection vulnerability in the setParentalRules function of the Totolink A8000RU version 7.1cu.643_b20200521 web management interface, allowing remote attackers to execute arbitrary commands by manipulating the 'enable' argument.
date: "2026-05-26T14:04:58Z"
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
  - id: CVE-2026-9478
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9478
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_352/README.md
  - https://vuldb.com/submit/813463
  - https://vuldb.com/vuln/365459
  - https://vuldb.com/vuln/365459/cti
  - https://www.totolink.net/
rules:
  - title: Detect Totolink CVE-2026-9478 Command Injection Attempt
    description: Detects CVE-2026-9478 exploitation — HTTP requests to /cgi-bin/cstecgi.cgi with shell metacharacters in the enable parameter indicative of a command injection attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect Totolink setParentalRules Command Injection via Web Management Interface
    description: Detects attempts to exploit CVE-2026-9478 by identifying suspicious requests to setParentalRules via the web management interface.
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

A critical vulnerability, CVE-2026-9478, has been discovered in the Totolink A8000RU router, specifically version 7.1cu.643_b20200521. The flaw resides within the Web Management Interface in the `/cgi-bin/cstecgi.cgi` file, affecting the `setParentalRules` function. By manipulating the `enable` argument, a remote attacker can inject arbitrary operating system commands. Publicly available exploits exist, increasing the likelihood of exploitation. This vulnerability allows unauthenticated remote attackers to gain complete control over the affected router, potentially leading to network compromise and data exfiltration. Given the ease of exploitation and the potential for widespread impact, this vulnerability poses a significant threat.

## Attack Chain

1. The attacker identifies a vulnerable Totolink A8000RU router running firmware version 7.1cu.643_b20200521.
2. The attacker sends a crafted HTTP request to the `/cgi-bin/cstecgi.cgi` endpoint.
3. The HTTP request targets the `setParentalRules` function within the CGI script.
4. The attacker injects malicious OS commands into the `enable` argument of the `setParentalRules` function.
5. The CGI script executes the injected OS commands due to insufficient input validation.
6. The attacker gains remote code execution on the router's operating system.
7. The attacker uses the compromised router as a pivot point to access other devices on the network.
8. The attacker may install malware, exfiltrate sensitive data, or disrupt network services.

## Impact

Successful exploitation of CVE-2026-9478 allows a remote attacker to execute arbitrary operating system commands on the affected Totolink A8000RU router. This can lead to complete compromise of the device, allowing the attacker to modify router settings, intercept network traffic, or use the router as a botnet node. Given the wide deployment of Totolink routers in homes and small businesses, a successful widespread attack could have significant impact, affecting potentially thousands of users.

## Recommendation

*   Apply available firmware updates from Totolink to patch CVE-2026-9478.
*   Deploy the Sigma rule "Detect Totolink CVE-2026-9478 Command Injection Attempt" to identify exploitation attempts in web server logs.
*   Monitor web server logs for requests to `/cgi-bin/cstecgi.cgi` containing shell metacharacters in the `enable` parameter, as detected by the Sigma rule.
*   Implement network segmentation to limit the impact of a compromised router on other network devices.
