---
title: Totolink A8000RU Remote Command Injection Vulnerability (CVE-2026-9454)
slug: 2026-05-totolink-rce
description: A remote command injection vulnerability (CVE-2026-9454) exists in the setOpenVpnCertGenerationCfg function of the Totolink A8000RU version 7.1cu.643_b20200521 web management interface, allowing unauthenticated attackers to execute arbitrary commands by manipulating the 'servername' argument.
date: "2026-05-26T14:02:38Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - cve
  - cve-2026-9454
  - command injection
  - rce
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
  - id: CVE-2026-9454
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9454
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_341/README.md
  - https://vuldb.com/submit/813447
  - https://vuldb.com/vuln/365435
  - https://vuldb.com/vuln/365435/cti
  - https://www.totolink.net/
rules:
  - title: Detect CVE-2026-9454 Exploitation via Web Request
    description: Detects CVE-2026-9454 exploitation — Attempts to exploit the Totolink A8000RU command injection vulnerability by detecting shell metacharacters in the servername parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect CVE-2026-9454 Exploitation via POST Request
    description: Detects CVE-2026-9454 exploitation — Attempts to exploit the Totolink A8000RU command injection vulnerability via POST request.
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

A critical vulnerability, CVE-2026-9454, has been identified in Totolink A8000RU router version 7.1cu.643_b20200521. The flaw resides within the web management interface, specifically in the `setOpenVpnCertGenerationCfg` function located in `/cgi-bin/cstecgi.cgi`. This vulnerability allows for remote, unauthenticated OS command injection through manipulation of the `servername` argument. Publicly available exploit code exists, increasing the likelihood of exploitation. Successful exploitation would allow an attacker to execute arbitrary commands on the router, potentially leading to complete system compromise.

## Attack Chain

1.  The attacker sends a malicious HTTP request to the `/cgi-bin/cstecgi.cgi` endpoint.
2.  The request targets the `setOpenVpnCertGenerationCfg` function.
3.  The attacker crafts the request to include shell metacharacters in the `servername` argument.
4.  The web management interface fails to properly sanitize the `servername` input.
5.  The unsanitized input is passed to a system call, resulting in command injection.
6.  The attacker's injected command is executed with the privileges of the web server process.
7.  The attacker gains remote code execution on the Totolink A8000RU device.
8.  The attacker could then install malware, modify router settings, or pivot to other devices on the network.

## Impact

Successful exploitation of CVE-2026-9454 grants an attacker the ability to execute arbitrary commands on the vulnerable Totolink A8000RU device. This can lead to complete compromise of the router, allowing attackers to eavesdrop on network traffic, modify DNS settings, create VPN tunnels, or use the compromised device as a foothold for further attacks on the internal network. Given the wide usage of Totolink routers, a large number of devices are potentially vulnerable.

## Recommendation

*   Apply available patches or firmware updates from Totolink to address CVE-2026-9454.
*   Deploy the Sigma rule `Detect CVE-2026-9454 Exploitation via Web Request` to identify exploitation attempts targeting the vulnerable endpoint and function.
*   Monitor web server logs for suspicious requests containing shell metacharacters in the `servername` parameter of requests to `/cgi-bin/cstecgi.cgi`.
