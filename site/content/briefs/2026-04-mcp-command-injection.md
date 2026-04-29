---
title: dvladimirov MCP Git Search API Command Injection Vulnerability
slug: 2026-04-mcp-command-injection
description: A command injection vulnerability (CVE-2026-7211) exists in the GitSearchRequest function of dvladimirov MCP up to version 0.1.0, allowing a remote attacker to execute arbitrary commands by manipulating the repo_url or pattern argument.
date: "2026-04-28T01:16:02Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - command-injection
  - vulnerability
  - git-search-api
vendors:
  - dvladimirov
products:
  - MCP
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7211
    cvss: 7.3
    epss: 0.01039
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7211
rules:
  - title: Detect MCP Git Search API Command Injection Attempt
    description: Detects potential command injection attempts against the dvladimirov MCP Git Search API by identifying shell metacharacters in the repo_url or pattern parameters.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect MCP Git Search API Access
    description: Detects access to the dvladimirov MCP Git Search API.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A command injection vulnerability has been identified in dvladimirov MCP (Monitoring and Configuration Platform) up to version 0.1.0. This vulnerability resides within the GitSearchRequest function located in the `mcp_server.py` file, specifically affecting the Git Search API component. Successful exploitation allows a remote attacker to inject and execute arbitrary commands on the underlying system. The vulnerability stems from insufficient sanitization of user-supplied input to the `repo_url` or `pattern` arguments. Publicly available exploits exist, increasing the risk of active exploitation. The project maintainers were notified through an issue report but have not yet addressed the vulnerability.

## Attack Chain

1.  The attacker identifies an instance of dvladimirov MCP running a version up to 0.1.0 with the Git Search API enabled.
2.  The attacker crafts a malicious HTTP request targeting the Git Search API endpoint (`/gitsearch`).
3.  Within the request, the attacker injects a command injection payload into either the `repo_url` or `pattern` argument. This payload leverages shell metacharacters (e.g., `;`, `|`, `&&`) to chain malicious commands.
4.  The MCP server receives the request and passes the unsanitized `repo_url` or `pattern` value to the GitSearchRequest function in `mcp_server.py`.
5.  The `GitSearchRequest` function executes the injected command via a system call, effectively bypassing intended functionality.
6.  The attacker gains arbitrary command execution on the server, potentially allowing them to read sensitive files, modify system configurations, or establish a reverse shell.
7.  The attacker uses the reverse shell to further explore the network and escalate privileges.

## Impact

Successful exploitation of this command injection vulnerability allows a remote attacker to execute arbitrary commands on the affected system. This can lead to complete system compromise, including data theft, modification, or destruction. Given the nature of MCP, which likely manages configurations and monitors other systems, a successful attack could cascade to other parts of the infrastructure, potentially affecting numerous systems across the network.

## Recommendation

*   Apply input validation and sanitization to the `repo_url` and `pattern` parameters within the `GitSearchRequest` function to prevent command injection.
*   Deploy the Sigma rule `Detect MCP Git Search API Command Injection Attempt` to detect exploitation attempts targeting CVE-2026-7211.
*   Monitor web server logs for suspicious requests containing shell metacharacters in the `repo_url` or `pattern` parameters as outlined in the Sigma rule and overview sections.
*   Consider isolating or taking offline affected MCP instances until a patch is available to mitigate the risks associated with CVE-2026-7211.
