---
title: OS Command Injection Vulnerability in p_69_branch_monkey_mcp Preview Endpoint (CVE-2026-7590)
slug: 2026-05-branch-monkey-mcp-command-injection
description: A remote attacker can inject OS commands by manipulating the dev_script argument in the Preview Endpoint of eyal-gor's p_69_branch_monkey_mcp (up to commit 69bc71874ce40050ef45fde5a435855f18af3373), leading to arbitrary code execution on the server.
date: "2026-05-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - web-application
  - cve
vendors:
  - eyal-gor
products:
  - p_69_branch_monkey_mcp
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7590
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7590
rules:
  - title: p_69_branch_monkey_mcp_command_injection
    description: Detects potential command injection attempts targeting the Preview Endpoint of p_69_branch_monkey_mcp by monitoring web server logs for suspicious parameters.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: p_69_branch_monkey_mcp_unexpected_process
    description: Detects unexpected processes spawned by the web server, which may indicate successful command injection in p_69_branch_monkey_mcp.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical OS command injection vulnerability, CVE-2026-7590, has been identified in the Preview Endpoint of eyal-gor's p_69_branch_monkey_mcp. This vulnerability affects versions up to commit 69bc71874ce40050ef45fde5a435855f18af3373. A remote attacker can exploit this flaw by manipulating the `dev_script` argument within the `branch_monkey_mcp/bridge_and_local_actions/routes/advanced.py` file.  Successful exploitation allows for arbitrary command execution on the host operating system. The exploit is publicly available, increasing the risk of widespread exploitation. The vendor has been notified but has not yet responded. The lack of versioning makes it difficult to determine the exact scope of affected installations.

## Attack Chain

1.  The attacker identifies a vulnerable instance of p_69_branch_monkey_mcp running a web server.
2.  The attacker crafts a malicious HTTP request targeting the Preview Endpoint.
3.  The request includes a payload in the `dev_script` argument designed to inject OS commands via the `branch_monkey_mcp/bridge_and_local_actions/routes/advanced.py` file.
4.  The web server processes the request, passing the attacker-controlled `dev_script` argument to a function that executes system commands without proper sanitization.
5.  The injected OS command is executed by the server, potentially with the privileges of the web server user. For example, an attacker could inject `ls -la` to list directory contents.
6.  The output of the injected command is returned to the attacker via the web server's response, confirming successful command execution.
7.  The attacker leverages the initial command execution to escalate privileges, install persistent backdoors, or move laterally within the network, depending on the server's configuration and accessible resources.
8.  The attacker achieves their final objective, such as data exfiltration, system compromise, or denial of service.

## Impact

Successful exploitation of CVE-2026-7590 allows a remote attacker to execute arbitrary OS commands on the affected server. This could lead to complete system compromise, including data theft, malware installation, and denial of service. The lack of version information makes it difficult to ascertain the number of vulnerable installations, but given the publicly available exploit, widespread exploitation is possible. Organizations using p_69_branch_monkey_mcp are at high risk.

## Recommendation

*   Monitor web server logs for suspicious requests targeting the Preview Endpoint and containing potentially malicious payloads in the `dev_script` parameter as described in the attack chain. Use the "p_69_branch_monkey_mcp_command_injection" Sigma rule.
*   Inspect process creation events for unexpected processes spawned by the web server, indicating potential command injection. Use the "p_69_branch_monkey_mcp_unexpected_process" Sigma rule.
*   Implement input validation and sanitization on the `dev_script` parameter in the `branch_monkey_mcp/bridge_and_local_actions/routes/advanced.py` file to prevent command injection.
*   Although specific vulnerable versions are unavailable, immediately investigate and patch any instances of `p_69_branch_monkey_mcp` due to the public exploit availability.
