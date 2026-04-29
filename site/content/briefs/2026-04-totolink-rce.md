---
title: Totolink A7100RU OS Command Injection Vulnerability
slug: 2026-04-totolink-rce
description: Totolink A7100RU version 7.4cu.2313_b20191024 is vulnerable to OS command injection via the setTracerouteCfg function in the /cgi-bin/cstecgi.cgi file, allowing remote attackers to execute arbitrary commands by manipulating the 'command' argument.
date: "2026-04-13T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - cve-2026-6131
  - command-injection
  - router
  - totolink
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-6131
    cvss: 9.8
    epss: 0.01254
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6131
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_182/README.md
  - https://vuldb.com/vuln/356995
rules:
  - title: Detect Totolink A7100RU Command Injection Attempt
    description: Detects potential command injection attempts targeting the setTracerouteCfg function in Totolink A7100RU routers.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect suspicious characters in web requests to cstecgi.cgi
    description: Detects suspicious characters in web requests to cstecgi.cgi which could indicate a command injection attempt
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-6131, has been identified in Totolink A7100RU router firmware version 7.4cu.2313_b20191024. This flaw resides within the CGI Handler component, specifically affecting the `setTracerouteCfg` function in the `/cgi-bin/cstecgi.cgi` file. The vulnerability allows for OS command injection by manipulating the `command` argument. Given that the exploit is publicly available, attackers can remotely execute arbitrary commands on affected devices. This poses a significant risk, potentially leading to full device compromise, network pivoting, and data exfiltration. Organizations using this router model should prioritize patching or mitigating this vulnerability to prevent potential exploitation.

## Attack Chain

1.  An attacker identifies a Totolink A7100RU router running firmware version 7.4cu.2313_b20191024.
2.  The attacker sends a crafted HTTP request to the `/cgi-bin/cstecgi.cgi` endpoint, targeting the `setTracerouteCfg` function.
3.  Within the HTTP request, the attacker manipulates the `command` argument to inject malicious OS commands.
4.  The CGI Handler processes the request, executing the injected commands with the privileges of the web server.
5.  The attacker gains arbitrary code execution on the router's operating system.
6.  The attacker can then establish a reverse shell to maintain persistent access.
7.  The attacker escalates privileges to gain root access to the device.
8.  Finally, the attacker can modify the router's configuration, install malware, or use the compromised device as a pivot point to access other devices on the network.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary commands on the affected Totolink A7100RU router. This could lead to complete device compromise, allowing the attacker to control the router's functionality, intercept network traffic, and potentially gain access to other devices on the network. Given the publicly available exploit, a large number of devices could be targeted, leading to widespread disruption of network services and potential data breaches.

## Recommendation

*   Apply any available patches or firmware updates from Totolink to address CVE-2026-6131.
*   Monitor web server logs for suspicious requests to `/cgi-bin/cstecgi.cgi` containing shell metacharacters or command injection attempts, as detailed in the attack chain.
*   Implement network intrusion detection system (IDS) rules to detect and block exploitation attempts targeting the `setTracerouteCfg` function based on the request patterns to `/cgi-bin/cstecgi.cgi`.
*   Deploy the Sigma rule provided below to detect command injection attempts in web server logs.
