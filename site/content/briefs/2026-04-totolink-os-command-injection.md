---
title: Totolink A7100RU OS Command Injection Vulnerability (CVE-2026-5677)
slug: 2026-04-totolink-os-command-injection
description: A remote OS command injection vulnerability (CVE-2026-5677) exists in the CsteSystem function of the /cgi-bin/cstecgi.cgi file in Totolink A7100RU firmware version 7.4cu.2313_b20191024 due to improper handling of the resetFlags argument.
date: "2026-04-06T19:16:30Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-5677
  - totolink
  - command-injection
  - network-device
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5677
    cvss: 7.3
    epss: 0.04857
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5677
  - https://github.com/Litengzheng/vuldb_new/blob/main/A7100RU/vul_184/README.md
  - https://vuldb.com/vuln/355504
rules:
  - title: Detect Totolink A7100RU CsteSystem Command Injection Attempt
    description: Detects attempts to exploit the CVE-2026-5677 command injection vulnerability in Totolink A7100RU routers by identifying requests to /cgi-bin/cstecgi.cgi with shell metacharacters in the resetFlags parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink A7100RU CsteSystem Access
    description: Detects access to the /cgi-bin/cstecgi.cgi on Totolink A7100RU routers.
    platform: sigma
    severity: low
    tactics:
      - discovery
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical OS command injection vulnerability, tracked as CVE-2026-5677, has been identified in Totolink A7100RU routers running firmware version 7.4cu.2313_b20191024. The vulnerability resides within the `CsteSystem` function of the `/cgi-bin/cstecgi.cgi` file. By manipulating the `resetFlags` argument, a remote attacker can inject and execute arbitrary operating system commands on the affected device. This exploit is publicly available, increasing the risk of widespread exploitation. Successful exploitation allows an attacker to gain complete control over the device, potentially leading to data theft, denial of service, or use of the router as part of a botnet.

## Attack Chain

1.  The attacker identifies a vulnerable Totolink A7100RU router with firmware version 7.4cu.2313_b20191024.
2.  The attacker sends a crafted HTTP request to the `/cgi-bin/cstecgi.cgi` endpoint.
3.  The HTTP request includes the `resetFlags` argument with a malicious payload containing OS commands.
4.  The `CsteSystem` function processes the request without proper sanitization of the `resetFlags` argument.
5.  The injected OS commands are executed with the privileges of the web server process.
6.  The attacker gains arbitrary code execution on the router's operating system.
7.  The attacker can then install persistent backdoors, modify router settings, or use the device for further attacks.

## Impact

Successful exploitation of CVE-2026-5677 allows a remote attacker to execute arbitrary commands on vulnerable Totolink A7100RU routers. This can lead to complete compromise of the device, enabling attackers to steal sensitive information, disrupt network services, or use the router as a launchpad for other attacks, such as botnet participation or man-in-the-middle attacks. Given the widespread use of Totolink routers, a successful large-scale exploitation could affect thousands of users.

## Recommendation

*   Deploy the Sigma rule `Detect Totolink A7100RU CsteSystem Command Injection Attempt` to your SIEM to identify malicious requests to the `/cgi-bin/cstecgi.cgi` endpoint.
*   Inspect web server logs for suspicious POST requests to `/cgi-bin/cstecgi.cgi` containing shell metacharacters in the `resetFlags` parameter to detect exploitation attempts (webserver logs).
