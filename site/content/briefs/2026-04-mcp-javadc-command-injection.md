---
title: idachev mcp-javadc OS Command Injection via HTTP Interface (CVE-2026-5802)
slug: 2026-04-mcp-javadc-command-injection
description: A remote command injection vulnerability (CVE-2026-5802) exists in idachev mcp-javadc up to version 1.2.4 via the HTTP Interface by manipulating the jarFilePath argument, allowing unauthenticated attackers to execute arbitrary OS commands.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - web-application
  - cve-2026-5802
vendors:
  - idachev
products:
  - mcp-javadc
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-5802
    cvss: 7.3
    epss: 0.01651
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5802
  - https://github.com/BruceJqs/public_exp/issues/2
  - https://github.com/idachev/mcp-javadc/
  - https://github.com/idachev/mcp-javadc/issues/7
  - https://vuldb.com/submit/786974
  - https://vuldb.com/vuln/356241
  - https://vuldb.com/vuln/356241/cti
rules:
  - title: Detect Suspicious JarFilePath Parameter in HTTP Request
    description: Detects suspicious HTTP requests targeting the HTTP Interface component with a malicious jarFilePath parameter, indicative of command injection attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Command Execution via Web Server
    description: Detects command execution originating from the web server process, which could be a result of command injection.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical OS command injection vulnerability, CVE-2026-5802, has been identified in idachev mcp-javadc, a Java decompiler, up to version 1.2.4. The vulnerability resides within the HTTP Interface component. By manipulating the `jarFilePath` argument, a remote attacker can inject and execute arbitrary operating system commands on the server. This vulnerability is remotely exploitable without authentication, increasing the severity. Publicly available exploits exist, potentially leading to widespread exploitation. The vendor has been notified through an issue report but has not yet responded.

## Attack Chain

1.  The attacker sends a malicious HTTP request to the vulnerable `mcp-javadc` server.
2.  The HTTP request targets the HTTP Interface component.
3.  The attacker crafts the request to manipulate the `jarFilePath` argument.
4.  The server-side code fails to properly sanitize the `jarFilePath` argument.
5.  The unsanitized `jarFilePath` argument is passed to an operating system command.
6.  The injected OS command is executed by the server with the privileges of the `mcp-javadc` process.
7.  The attacker gains arbitrary code execution on the server.
8.  The attacker can then perform further actions, such as data exfiltration, lateral movement, or denial of service.

## Impact

Successful exploitation of CVE-2026-5802 allows unauthenticated remote attackers to execute arbitrary operating system commands on the affected system. This can lead to complete system compromise, including data theft, malware installation, and denial of service. As this vulnerability affects a software development tool, successful attacks could compromise software build pipelines, leading to supply chain attacks. The number of potential victims is currently unknown, but given the publicly available exploit, the risk of widespread exploitation is high.

## Recommendation

*   Apply available patches for `mcp-javadc` if they become available.
*   Deploy the Sigma rule `Detect Suspicious JarFilePath Parameter in HTTP Request` to identify exploitation attempts targeting the `jarFilePath` parameter.
*   Monitor web server logs for unusual HTTP requests containing suspicious characters or command sequences within the `jarFilePath` parameter.
*   Implement input validation and sanitization measures on the server-side to prevent command injection.
*   Place the affected server in an isolated network segment to limit the impact of potential compromise.
