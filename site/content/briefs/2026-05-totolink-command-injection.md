---
title: Totolink A8000RU Command Injection Vulnerability (CVE-2026-9433)
slug: 2026-05-totolink-command-injection
description: A remote command injection vulnerability exists in the Totolink A8000RU router version 7.1cu.643_b20200521 due to improper neutralization of special elements when handling the 'enable' argument of the 'setMacFilterRules' function, allowing unauthenticated attackers to execute arbitrary OS commands.
date: "2026-05-26T13:59:45Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - cve
  - router
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
  - id: CVE-2026-9433
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9433
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_354/README.md
  - https://vuldb.com/submit/813906
  - https://vuldb.com/vuln/365414
  - https://vuldb.com/vuln/365414/cti
  - https://www.totolink.net/
rules:
  - title: Detect CVE-2026-9433 Exploitation Attempt via Crafted HTTP Request
    description: Detects CVE-2026-9433 exploitation attempt — HTTP request to /cgi-bin/cstecgi.cgi with shell metacharacters in the 'enable' parameter, indicating a command injection attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Suspicious Process Execution from Web Server on Totolink Router
    description: Detects suspicious process execution from the web server process on Totolink router, which can be an indicator of command injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical command injection vulnerability, CVE-2026-9433, has been identified in Totolink A8000RU router version 7.1cu.643_b20200521. The vulnerability resides within the web management interface, specifically in the `/cgi-bin/cstecgi.cgi` script. By manipulating the `enable` argument passed to the `setMacFilterRules` function, an attacker can inject arbitrary OS commands. This vulnerability is remotely exploitable without authentication and public exploits are available, significantly increasing the risk of widespread exploitation. Successful exploitation can lead to complete compromise of the router, allowing attackers to control network traffic, steal sensitive information, or use the router as a botnet node.

## Attack Chain

1.  The attacker identifies a vulnerable Totolink A8000RU router running firmware version 7.1cu.643_b20200521.
2.  The attacker sends a crafted HTTP request to the `/cgi-bin/cstecgi.cgi` endpoint.
3.  The HTTP request targets the `setMacFilterRules` function, manipulating the `enable` argument.
4.  The `enable` argument contains embedded OS commands using shell metacharacters (e.g., `;`, `|`, `&&`).
5.  The `setMacFilterRules` function fails to properly sanitize the `enable` argument before passing it to a system call.
6.  The injected OS command is executed with the privileges of the web server process.
7.  The attacker gains arbitrary code execution on the router's operating system.
8.  The attacker can then use this access to modify router settings, install malware, or pivot to other devices on the network.

## Impact

Successful exploitation of CVE-2026-9433 allows an unauthenticated attacker to execute arbitrary commands on the affected Totolink A8000RU router. This can lead to a complete compromise of the device, potentially affecting all devices on the local network. Given the availability of public exploits, a widespread attack targeting vulnerable Totolink routers is highly likely, potentially impacting thousands of home and small business networks.

## Recommendation

*   Apply any available patches or firmware updates released by Totolink to address CVE-2026-9433.
*   Deploy the Sigma rule "Detect CVE-2026-9433 Exploitation Attempt via Crafted HTTP Request" to identify exploitation attempts based on requests to `/cgi-bin/cstecgi.cgi` with shell metacharacters in the `enable` parameter within your web server logs.
*   Implement network segmentation to limit the impact of compromised routers on other network devices.
*   Monitor network traffic for suspicious outbound connections originating from Totolink A8000RU devices, as this may indicate a compromised device attempting to establish a command and control channel.
