---
title: chatboxai chatbox Command Injection Vulnerability (CVE-2026-6130)
slug: 2024-01-10-chatboxai-command-injection
description: A command injection vulnerability (CVE-2026-6130) exists in chatboxai chatbox versions up to 1.20.0, allowing a remote attacker to execute arbitrary OS commands by manipulating the 'args/env' argument in the StdioClientTransport function, potentially leading to complete system compromise.
date: "2024-01-10T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - vulnerability
  - chatboxai
  - CVE-2026-6130
vendors:
  - chatboxai
products:
  - chatboxai chatbox
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-6130
    cvss: 7.3
    epss: 0.01715
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6130
rules:
  - title: Detect chatboxai chatbox Command Injection Attempt via URI
    description: Detects potential command injection attempts targeting chatboxai chatbox by identifying suspicious characters or command sequences in the URI query string. Tune the rule by adjusting the 'suspicious_commands' list to match your environment and known legitimate uses.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1202
    data_sources:
      - webserver
      - linux
  - title: Detect chatboxai chatbox Command Injection Attempt via HTTP Request Body
    description: Detects potential command injection attempts targeting chatboxai chatbox by identifying suspicious characters or command sequences in the HTTP request body. This rule should be enabled if the application processes arguments passed in the request body.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1202
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical command injection vulnerability has been identified in chatboxai chatbox, affecting versions up to 1.20.0. The vulnerability resides within the `StdioClientTransport` function in the `src/main/mcp/ipc-stdio-transport.ts` file of the Model Context Protocol Server Management System. An attacker can exploit this flaw by manipulating the `args/env` argument, injecting arbitrary OS commands that the server will execute. This vulnerability can be exploited remotely, and a public exploit is currently available, increasing the risk of widespread exploitation. The vendor has been notified but has not yet addressed the issue. Successful exploitation allows attackers to gain full control of the affected system.

## Attack Chain

1.  Attacker identifies a chatboxai chatbox instance running a vulnerable version (<= 1.20.0).
2.  The attacker crafts a malicious request targeting the `StdioClientTransport` function in `src/main/mcp/ipc-stdio-transport.ts`.
3.  The crafted request includes manipulated `args` or `env` parameters designed to inject OS commands.
4.  The chatboxai application processes the request and passes the attacker-controlled `args/env` to a system call.
5.  The injected OS command is executed by the server with the privileges of the chatboxai process.
6.  The attacker gains initial access to the server, potentially as the user running the chatboxai application.
7.  The attacker can then perform privilege escalation, lateral movement, and further malicious activities within the compromised environment.
8.  The final objective could be data exfiltration, installation of malware, or disruption of services.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary OS commands on the affected system. This can lead to complete system compromise, including unauthorized access to sensitive data, installation of malware, and disruption of services. Given the availability of a public exploit, unpatched chatboxai chatbox instances are at high risk of being targeted. The severity of the impact is compounded by the lack of vendor response, increasing the window of opportunity for attackers. The number of potential victims and the specific sectors targeted are currently unknown, but any organization using chatboxai chatbox is potentially vulnerable.

## Recommendation

*   Deploy the Sigma rule provided in this brief to your SIEM to detect exploitation attempts targeting the `StdioClientTransport` function.
*   Monitor web server logs for suspicious requests containing potentially malicious commands within the `args` or `env` parameters, focusing on the `cs-uri-query` field.
*   Consider implementing a web application firewall (WAF) rule to filter requests containing suspicious command injection payloads in `args` and `env`.
*   Although a patch is not yet available, monitor the vendor's website and security advisories for updates and apply patches immediately when released.
