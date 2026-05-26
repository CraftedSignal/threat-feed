---
title: Totolink A8000RU Command Injection Vulnerability (CVE-2026-9407)
slug: 2026-05-totolink-rce
description: CVE-2026-9407 is a critical command injection vulnerability in the Totolink A8000RU router's web management interface, specifically in the setFirewallType function, allowing remote attackers to execute arbitrary OS commands.
date: "2026-05-26T13:58:51Z"
type: advisory
types:
  - advisory
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
  - id: CVE-2026-9407
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9407
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_339/README.md
  - https://vuldb.com/submit/813442
  - https://vuldb.com/vuln/365388
  - https://vuldb.com/vuln/365388/cti
  - https://www.totolink.net/
rules:
  - title: Detects CVE-2026-9407 Exploitation — Totolink Firewall Type Command Injection
    description: Detects CVE-2026-9407 exploitation — HTTP requests to /cgi-bin/cstecgi.cgi with shell metacharacters in the firewallType parameter indicating a command injection attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detects CVE-2026-9407 Exploitation — Totolink Firewall Type Command Injection (GET Method)
    description: Detects CVE-2026-9407 exploitation — HTTP GET requests to /cgi-bin/cstecgi.cgi with shell metacharacters in the firewallType parameter indicating a command injection attempt.
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

A command injection vulnerability, tracked as CVE-2026-9407, affects the Totolink A8000RU router, version 7.1cu.643_b20200521. The vulnerability resides in the web management interface's `/cgi-bin/cstecgi.cgi` file, specifically within the `setFirewallType` function. By manipulating the `firewallType` argument, a remote attacker can inject arbitrary OS commands. Publicly available exploits exist, increasing the risk of exploitation. Successful exploitation allows the attacker to gain complete control over the affected device, potentially leading to data theft, network compromise, or use of the router as part of a botnet.

## Attack Chain

1.  The attacker identifies a vulnerable Totolink A8000RU router with version 7.1cu.643_b20200521 exposed to the internet.
2.  The attacker sends a crafted HTTP request to the `/cgi-bin/cstecgi.cgi` endpoint.
3.  The malicious request targets the `setFirewallType` function.
4.  The `firewallType` argument within the HTTP request is manipulated to include OS command injection payloads (e.g., using shell metacharacters like `;`, `|`, `&&`).
5.  The web server processes the request without proper sanitization of the `firewallType` argument.
6.  The injected OS command is executed by the underlying operating system with the privileges of the web server process.
7.  The attacker gains arbitrary code execution on the router.
8.  The attacker can then use the compromised router for malicious purposes, such as botnet activities or pivoting to internal networks.

## Impact

Successful exploitation of CVE-2026-9407 grants attackers complete control over the affected Totolink A8000RU routers. This allows them to perform various malicious activities, including stealing sensitive information, modifying router configurations, using the router as a node in a botnet, or gaining a foothold in the network to which the router is connected. Given the ease of exploitation and the availability of public exploits, this vulnerability poses a significant threat to users of the affected router model.

## Recommendation

*   Deploy the Sigma rule to detect exploitation attempts targeting the vulnerable `setFirewallType` function in the `/cgi-bin/cstecgi.cgi` file.
*   Implement network segmentation to limit the impact of a compromised router on other internal systems.
*   Consider using a web application firewall (WAF) to filter out malicious requests targeting the vulnerable endpoint.
*   Monitor web server logs for suspicious activity, such as unusual requests to `/cgi-bin/cstecgi.cgi` or the presence of shell metacharacters in the `firewallType` argument as detected by the provided Sigma rule.
