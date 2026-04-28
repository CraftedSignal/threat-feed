---
title: Totolink A7100RU OS Command Injection Vulnerability (CVE-2026-5692)
slug: 2026-04-totolink-rce
description: CVE-2026-5692 is an OS command injection vulnerability in the Totolink A7100RU router that allows remote attackers to execute arbitrary commands by manipulating the 'enable' argument in the setGameSpeedCfg function.
date: "2026-04-07T00:16:20Z"
severities:
  - critical
tags:
  - totolink
  - command-injection
  - cve-2026-5692
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-5692
    cvss: 7.3
    epss: 0.01184
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5692
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_190/README.md
  - https://vuldb.com/vuln/355519
rules:
  - title: Detect Totolink A7100RU Command Injection Attempt
    description: Detects potential command injection attempts targeting the Totolink A7100RU router vulnerability (CVE-2026-5692) by monitoring requests to the cstecgi.cgi endpoint with suspicious parameters.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink A7100RU Access to cstecgi.cgi with no Referer
    description: Detects potential exploitation of Totolink A7100RU router by monitoring requests to cstecgi.cgi endpoint with a missing Referer header.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-5692, has been identified in Totolink A7100RU router firmware version 7.4cu.2313_b20191024. This vulnerability resides within the `setGameSpeedCfg` function in the `/cgi-bin/cstecgi.cgi` file. Successful exploitation allows remote attackers to inject and execute arbitrary OS commands on the affected device. The vulnerability is triggered through manipulation of the `enable` argument. Publicly available exploit code exists, increasing the likelihood of exploitation. This vulnerability poses a significant risk, potentially allowing attackers to gain complete control of vulnerable routers.

## Attack Chain

1.  The attacker identifies a Totolink A7100RU router running firmware version 7.4cu.2313_b20191024 exposed to the internet.
2.  The attacker crafts a malicious HTTP request targeting the `/cgi-bin/cstecgi.cgi` endpoint.
3.  Within the HTTP request, the attacker manipulates the `enable` argument of the `setGameSpeedCfg` function.
4.  The attacker injects an OS command into the `enable` argument, for example, using shell metacharacters to chain commands.
5.  The router's backend CGI script processes the malicious input without proper sanitization.
6.  The injected OS command is executed with the privileges of the web server process.
7.  The attacker gains remote code execution on the router.
8.  The attacker can then use this access to further compromise the network, change DNS settings, or use the device in a botnet.

## Impact

Successful exploitation of CVE-2026-5692 allows a remote attacker to execute arbitrary OS commands on the vulnerable Totolink A7100RU router. This can lead to complete device compromise, including the ability to modify router settings, intercept network traffic, and potentially pivot to other devices on the network. Given the widespread use of these routers, a large number of devices could be vulnerable. Successful exploitation allows attackers to create botnets, perform man-in-the-middle attacks, or disrupt network services.

## Recommendation

*   Deploy the Sigma rule `Detect Totolink A7100RU Command Injection Attempt` to identify exploitation attempts targeting this vulnerability by looking for requests to `/cgi-bin/cstecgi.cgi` with suspicious parameters (log source: webserver).
*   Monitor web server logs for requests to `/cgi-bin/cstecgi.cgi` containing shell metacharacters or other suspicious patterns in the `cs-uri-query` field to detect command injection attempts (log source: webserver).
*   Apply available patches or firmware updates released by Totolink to address CVE-2026-5692 as soon as they become available.
