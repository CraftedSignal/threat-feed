---
title: Totolink A8000RU Command Injection Vulnerability (CVE-2026-9457)
slug: 2026-05-totolink-command-injection
description: Totolink A8000RU version 7.1cu.643_b20200521 is vulnerable to command injection via the UploadFirmwareFile function within the Web Management Interface component's /cgi-bin/cstecgi.cgi file, allowing a remote attacker to inject and execute arbitrary OS commands by manipulating the FileName argument.
date: "2026-05-26T14:03:31Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - cve
  - command injection
  - router
  - web application
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
  - id: CVE-2026-9457
    cvss: 9.8
    epss: 0.00892
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9457
  - https://github.com/Litengzheng/vuldb_new2/blob/main/A8000RU/vul_343/README.md
  - https://vuldb.com/submit/813454
  - https://vuldb.com/vuln/365438
  - https://vuldb.com/vuln/365438/cti
  - https://www.totolink.net/
rules:
  - title: Detect CVE-2026-9457 Exploitation — Totolink Command Injection Attempt
    description: Detects CVE-2026-9457 exploitation — HTTP POST request to cstecgi.cgi with shell metacharacters in the FileName parameter, indicating a command injection attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
  - title: Detect Suspicious Web Requests to cstecgi.cgi
    description: Detects suspicious web requests to cstecgi.cgi which may indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    data_sources:
      - webserver
rules_count: 2
---

A critical vulnerability, CVE-2026-9457, exists in Totolink A8000RU router version 7.1cu.643_b20200521. This flaw resides within the Web Management Interface, specifically affecting the `UploadFirmwareFile` function located in `/cgi-bin/cstecgi.cgi`. An attacker can exploit this vulnerability by manipulating the `FileName` argument during a firmware upload, leading to arbitrary OS command injection. The vulnerability is remotely exploitable and has a publicly disclosed exploit, posing a significant risk to unpatched devices.

## Attack Chain

1.  Attacker identifies a vulnerable Totolink A8000RU router running firmware version 7.1cu.643_b20200521.
2.  The attacker sends a crafted HTTP POST request to `/cgi-bin/cstecgi.cgi` targeting the `UploadFirmwareFile` function.
3.  The POST request includes a malicious `FileName` parameter containing OS command injection payloads (e.g., using shell metacharacters like `;`, `|`, or `&&`).
4.  The vulnerable `UploadFirmwareFile` function fails to properly sanitize or validate the `FileName` argument.
5.  The application executes the injected OS command within the context of the device's operating system.
6.  The attacker gains remote code execution on the router.
7.  The attacker may then install malware, change the router's configuration, or use the device as part of a botnet.
8.  The attacker may attempt to pivot to other devices on the local network.

## Impact

Successful exploitation of CVE-2026-9457 allows an unauthenticated remote attacker to execute arbitrary OS commands on the vulnerable Totolink A8000RU router. This can lead to complete compromise of the device, allowing the attacker to control the router's functionality, intercept network traffic, or use the device for malicious purposes such as botnet participation or lateral movement within the network. Given the high CVSS score of 9.8, this vulnerability poses a significant risk to users of the affected router model and firmware version.

## Recommendation

*   Monitor webserver logs for POST requests to `/cgi-bin/cstecgi.cgi` with suspicious characters in the `FileName` parameter, using the Sigma rule "Detect CVE-2026-9457 Exploitation — Totolink Command Injection Attempt".
*   Apply available firmware updates from Totolink to patch CVE-2026-9457.
*   Implement input validation and sanitization measures on the `UploadFirmwareFile` function to prevent OS command injection.
*   Deploy the Sigma rule "Detect Suspicious Web Requests to cstecgi.cgi" to identify potentially malicious requests to the affected endpoint.
*   Regularly audit and patch network devices for known vulnerabilities.
