---
title: AVideo OS Command Injection Vulnerability (CVE-2026-63304)
slug: 2026-07-avideo-command-injection
description: AVideo versions up to and including 29.0 are vulnerable to an OS command injection (CVE-2026-63304) in the `listFFmpegProcesses()` function within `plugin/API/standAlone/functions.php`, allowing attackers to craft an encrypted `codeToExec` payload to bypass single-quote escaping and execute arbitrary operating system commands as the web-server user, leading to remote code execution.
date: "2026-07-16T13:20:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - os-command-injection
  - rce
  - web-vulnerability
  - cve
vendors:
  - WWBN
products:
  - AVideo (through 29.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers who can craft a valid encrypted codeToExec payload can break out of the single-quoted grep context and execute arbitrary OS commands as the web-server user.
    confidence_band: high
cves:
  - id: CVE-2026-63304
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63304
  - https://github.com/WWBN/AVideo/security/advisories/GHSA-j44m-77cc-p3cc
  - https://www.vulncheck.com/advisories/avideo-through-os-command-injection-via-listffmpegprocesses
iocs:
  - type: url
    value: https://github.com/WWBN/AVideo/security/advisories/GHSA-j44m-77cc-p3cc
  - type: url
    value: https://www.vulncheck.com/advisories/avideo-through-os-command-injection-via-listffmpegprocesses
ioc_counts:
  url: 2
rules:
  - title: Detects CVE-2026-63304 Exploitation - AVideo OS Command Injection
    description: Detects CVE-2026-63304 exploitation attempts by identifying HTTP requests to the vulnerable AVideo endpoint with OS command injection patterns in query parameters.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1059.004
    data_sources:
      - webserver
rules_count: 1
---

AVideo, a video content management system, through version 29.0, contains a critical OS command injection vulnerability, tracked as CVE-2026-63304. This flaw resides in the `listFFmpegProcesses()` function, located in `plugin/API/standAlone/functions.php`. The vulnerability arises because the function incorrectly interpolates unsanitized keyword parameters inside single quotes without proper escaping, specifically within a `grep` command context. Threat actors capable of crafting a valid encrypted `codeToExec` payload can exploit this weakness to break out of the single-quoted context. This allows them to inject and execute arbitrary operating system commands with the privileges of the web-server user, posing a significant risk of remote code execution, data compromise, and full system control. The vulnerability was published by NVD on July 16, 2026.

## Attack Chain

1. Attacker identifies a publicly accessible AVideo instance vulnerable to CVE-2026-63304 (versions up to 29.0).
2. Attacker crafts a specially designed, encrypted `codeToExec` payload containing OS command injection characters and desired commands.
3. The payload is engineered to escape the single-quoted `grep` command context within the vulnerable `listFFmpegProcesses()` function.
4. Attacker sends an HTTP request (likely POST or GET, depending on parameter handling) to the `plugin/API/standAlone/functions.php` endpoint, including the malicious `codeToExec` payload.
5. The `listFFmpegProcesses()` function receives and processes the request, incorporating the unsanitized `codeToExec` parameter into an internal `grep` command.
6. Due to the lack of proper escaping, the injected commands break out of the `grep` context and are executed by the underlying operating system.
7. The commands run with the privileges of the web-server user, enabling remote code execution on the AVideo server.

## Impact

Successful exploitation of CVE-2026-63304 leads to arbitrary OS command execution on the AVideo server, operating under the privileges of the web-server user. This level of access grants attackers the ability to take full control of the compromised server, install backdoors, exfiltrate sensitive data, deface the website, or use the server as a platform for further attacks on the internal network. The high CVSS score of 8.1 reflects the severe consequences of this vulnerability, which can lead to complete compromise of confidentiality, integrity, and availability of the affected system.

## Recommendation

* Patch CVE-2026-63304 on all AVideo instances immediately by upgrading to a patched version or applying vendor-recommended fixes.
* Deploy the Sigma rule provided in this brief to your SIEM to detect attempts at exploiting OS command injection patterns in web requests.
* Monitor web server access logs for requests to `plugin/API/standAlone/functions.php` containing unusual characters or patterns indicative of command injection as described in the `Detects CVE-2026-63304 Exploitation` rule.
* Review network firewall and web application firewall (WAF) logs for indicators of attacks against the `plugin/API/standAlone/functions.php` endpoint.
