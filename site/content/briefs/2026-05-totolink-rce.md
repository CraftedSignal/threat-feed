---
title: Totolink A8000RU OS Command Injection Vulnerability (CVE-2026-9405)
slug: 2026-05-totolink-rce
description: CVE-2026-9405 is a critical vulnerability in Totolink A8000RU firmware that allows unauthenticated remote attackers to execute arbitrary OS commands via the web management interface.
date: "2026-05-26T13:58:09Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - command injection
  - rce
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
  - id: CVE-2026-9405
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9405
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_337/README.md
  - https://vuldb.com/submit/813440
  - https://vuldb.com/vuln/365386
  - https://vuldb.com/vuln/365386/cti
  - https://www.totolink.net/
rules:
  - title: Detect CVE-2026-9405 Exploitation Attempt
    description: Detects CVE-2026-9405 exploitation attempt — HTTP request to cstecgi.cgi with OS command injection in the enable parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-9405 Post-Exploitation Activity
    description: Detects CVE-2026-9405 post-exploitation activity — Unexpected processes spawned by the web server.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical security flaw, CVE-2026-9405, has been identified in Totolink A8000RU router firmware version 7.1cu.643_b20200521. This vulnerability resides within the Web Management Interface, specifically in the `setGameSpeedCfg` function of the `/cgi-bin/cstecgi.cgi` file. By manipulating the `enable` argument, an unauthenticated remote attacker can inject and execute arbitrary operating system commands on the device. Public exploits are available, increasing the risk of widespread exploitation. The vulnerability allows for complete compromise of affected routers.

## Attack Chain

1.  An attacker sends an HTTP request to the `/cgi-bin/cstecgi.cgi` endpoint on the Totolink A8000RU router.
2.  The request targets the `setGameSpeedCfg` function.
3.  The attacker crafts the HTTP request to include a malicious payload within the `enable` argument. This payload contains OS command injection sequences.
4.  The vulnerable `setGameSpeedCfg` function fails to properly sanitize the `enable` argument.
5.  The unsanitized `enable` argument is passed to a system call, resulting in the execution of the injected OS command.
6.  The injected command executes with the privileges of the web server process.
7.  The attacker gains arbitrary code execution on the router's operating system.
8.  The attacker can then use this access to modify router settings, install malware, or pivot to other devices on the network.

## Impact

Successful exploitation of CVE-2026-9405 allows a remote attacker to execute arbitrary commands on the vulnerable Totolink A8000RU router. This can lead to complete compromise of the device, including data theft, modification of router settings, and potential use of the router as a botnet node. Given the ease of exploitation and the availability of public exploits, a wide range of Totolink A8000RU users are at risk.

## Recommendation

*   Deploy the Sigma rule "Detect CVE-2026-9405 Exploitation Attempt" to your SIEM to identify attempts to exploit this vulnerability via HTTP requests to `/cgi-bin/cstecgi.cgi` with malicious payloads in the `enable` argument.
*   Apply the Sigma rule "Detect CVE-2026-9405 Post-Exploitation Activity" to detect unusual processes spawned by the web server that may indicate successful exploitation.
*   Monitor web server logs for requests to `/cgi-bin/cstecgi.cgi` with the `enable` parameter containing shell metacharacters as defined in the IOC table.
