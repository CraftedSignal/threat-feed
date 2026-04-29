---
title: Toowiredd chatgpt-mcp-server OS Command Injection Vulnerability
slug: 2026-04-chatgpt-mcp-server-cmd-injection
description: Toowiredd chatgpt-mcp-server up to version 0.1.0 is vulnerable to OS command injection via the file src/services/docker.service.ts of the component MCP/HTTP, allowing for remote exploitation.
date: "2026-04-26T22:17:33Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cve-2026-7061
  - command-injection
  - webserver
vendors:
  - Toowiredd
products:
  - chatgpt-mcp-server
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7061
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7061
  - https://github.com/Toowiredd/chatgpt-mcp-server/
  - https://github.com/Toowiredd/chatgpt-mcp-server/issues/8
  - https://github.com/wing3e/public_exp/issues/28
  - https://vuldb.com/submit/798613
  - https://vuldb.com/vuln/359636
  - https://vuldb.com/vuln/359636/cti
rules:
  - title: Detect Suspicious chatgpt-mcp-server Command Injection Attempts
    description: Detects potential command injection attempts targeting chatgpt-mcp-server by analyzing HTTP request URIs for suspicious patterns.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious chatgpt-mcp-server Child Processes
    description: Detects potential exploitation of chatgpt-mcp-server by monitoring for suspicious child processes spawned by it.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Toowiredd chatgpt-mcp-server, specifically versions up to 0.1.0, contains an OS command injection vulnerability within the `src/services/docker.service.ts` file of the MCP/HTTP component. This flaw allows for remote exploitation, potentially enabling attackers to execute arbitrary commands on the underlying operating system. The vulnerability, identified as CVE-2026-7061, has a publicly available exploit, increasing the risk of exploitation. The project maintainers were notified via an issue report but have not yet addressed the vulnerability, making it crucial for defenders to implement mitigation and detection measures. This poses a significant risk to systems running vulnerable versions of chatgpt-mcp-server, as successful exploitation could lead to complete system compromise.

## Attack Chain

1.  The attacker identifies a vulnerable instance of Toowiredd chatgpt-mcp-server running version 0.1.0 or earlier.
2.  The attacker crafts a malicious HTTP request targeting the MCP/HTTP component.
3.  The request exploits the command injection vulnerability in `src/services/docker.service.ts`.
4.  The server-side code improperly sanitizes input, allowing the attacker to inject OS commands.
5.  The injected OS command is executed by the server with the privileges of the chatgpt-mcp-server process.
6.  The attacker gains initial access to the system.
7.  The attacker leverages the initial access to escalate privileges or move laterally within the network.
8.  The attacker achieves their objective, such as data exfiltration, deploying malware, or disrupting services.

## Impact

Successful exploitation of this OS command injection vulnerability (CVE-2026-7061) in Toowiredd chatgpt-mcp-server can lead to complete system compromise. Attackers can execute arbitrary commands, potentially leading to data breaches, service disruption, or the deployment of malicious software. Given the public availability of the exploit, organizations using this software are at a heightened risk of attack. The lack of a patch from the project maintainers further exacerbates the risk, making proactive detection and mitigation measures essential.

## Recommendation

*   Monitor web server logs for suspicious HTTP requests targeting the MCP/HTTP component of chatgpt-mcp-server, focusing on requests that might be attempting command injection (log source: webserver, product: linux).
*   Deploy the Sigma rule "Detect Suspicious chatgpt-mcp-server Command Injection Attempts" to identify exploitation attempts in web server logs.
*   Restrict access to the chatgpt-mcp-server instance to minimize the attack surface.
*   Consider deploying a web application firewall (WAF) to filter out malicious requests.
*   Monitor child processes spawned by the chatgpt-mcp-server process for unexpected or malicious commands (log source: process_creation, product: linux).
