---
title: Tenda HG3 2.0 Command Injection Vulnerability
slug: 2026-04-tenda-hg3-command-injection
description: Tenda HG3 2.0 is vulnerable to command injection; by manipulating the datasize argument in the formTracert function of the /boaform/formTracert file, a remote attacker can inject commands.
date: "2026-04-27T22:16:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - cve-2026-7160
  - tenda
vendors:
  - Tenda
products:
  - HG3 2.0
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7160
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7160
  - https://vuldb.com/submit/802079
  - https://vuldb.com/vuln/359759
  - https://vuldb.com/vuln/359759/cti
  - https://www.notion.so/33e0c75766a880488924cf24523acf6c
  - https://www.tenda.com.cn/
rules:
  - title: Detect Tenda HG3 Command Injection Attempt
    description: Detects potential command injection attempts targeting Tenda HG3 routers via the formTracert interface.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda HG3 Web Server Errors
    description: Detects web server errors from Tenda HG3 routers which could indicate exploit attempts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Tenda HG3 2.0 is vulnerable to a command injection vulnerability (CVE-2026-7160) affecting the formTracert function in the /boaform/formTracert file. A remote attacker can exploit this by manipulating the datasize argument to inject arbitrary commands into the system. The vulnerability has a CVSS v3.1 score of 8.8, indicating a high severity. Public disclosure and potential exploitation make this a critical issue for users of the Tenda HG3 2.0 router. Successful exploitation allows an attacker to execute arbitrary commands on the device, potentially leading to complete system compromise.

## Attack Chain

1.  The attacker identifies a vulnerable Tenda HG3 2.0 router with an exposed web interface.
2.  The attacker crafts a malicious HTTP request targeting the /boaform/formTracert endpoint.
3.  The malicious request includes a manipulated datasize argument designed to inject a command.
4.  The web server processes the request and passes the manipulated datasize argument to the formTracert function.
5.  The formTracert function fails to properly sanitize the input, allowing the injected command to be executed by the system.
6.  The injected command executes with the privileges of the web server process.
7.  The attacker gains arbitrary code execution on the router.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary commands on the Tenda HG3 2.0 router. This can lead to complete compromise of the device, including modification of router settings, interception of network traffic, and potential use of the router as a botnet node. Given the high base score of 8.8, this poses a significant risk to affected users.

## Recommendation

*   Apply available patches or firmware updates provided by Tenda to address CVE-2026-7160.
*   Monitor web server logs for suspicious POST requests to `/boaform/formTracert` with unusual `datasize` parameters, as covered by the Sigma rule "Detect Tenda HG3 Command Injection Attempt".
*   Implement network intrusion detection system (IDS) rules to detect and block exploit attempts targeting this vulnerability.
