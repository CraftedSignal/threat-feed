---
title: 54yyyu code-mcp Command Injection Vulnerability (CVE-2026-7812)
slug: 2026-05-code-mcp-command-injection
description: A command injection vulnerability (CVE-2026-7812) exists in the git_operation function of 54yyyu code-mcp's MCP Tool, allowing remote attackers to execute arbitrary commands by manipulating the operation argument.
date: "2026-05-05T05:16:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - web-application
  - cve-2026-7812
vendors:
  - 54yyyu
products:
  - code-mcp
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7812
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7812
rules:
  - title: Detect Suspicious Git Operation Requests
    description: Detects suspicious POST requests to the git_operation endpoint in src/code_mcp/server.py, indicative of command injection attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Processes Spawned by Code-MCP
    description: Detects suspicious processes spawned by the code-mcp application or related processes, which could be a sign of successful command injection.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A command injection vulnerability has been identified in 54yyyu's code-mcp, specifically affecting versions up to commit 4cfc4643541a110c906d93635b391bf7e357f4a8. The vulnerability resides in the `git_operation` function within `src/code_mcp/server.py` of the MCP Tool component. This flaw allows a remote attacker to inject and execute arbitrary commands by manipulating the `operation` argument. The exploit is publicly available, increasing the risk of exploitation. 54yyyu employs a continuous delivery model with rolling releases, making it difficult to pinpoint specific vulnerable versions and updated releases. The project maintainers were notified of the vulnerability through an issue report but have not yet provided a response or patch.

## Attack Chain

1.  The attacker identifies a publicly accessible instance of 54yyyu code-mcp running a vulnerable version (<= 4cfc4643541a110c906d93635b391bf7e357f4a8).
2.  The attacker crafts a malicious HTTP request targeting the `git_operation` function in `src/code_mcp/server.py`.
3.  The malicious request includes a crafted `operation` argument containing shell commands.
4.  The `git_operation` function, without proper sanitization, passes the attacker-controlled `operation` argument to a system call.
5.  The system executes the injected commands, potentially allowing the attacker to execute arbitrary code on the server.
6.  The attacker gains initial access and may attempt to escalate privileges.
7.  The attacker moves laterally within the network, compromising other systems and data.
8.  The attacker achieves their final objective, which could include data exfiltration, ransomware deployment, or system disruption.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary commands on the affected system. Due to the lack of specific versioning information and response from the vendor, the exact number of vulnerable installations is unknown. This vulnerability could lead to complete system compromise, data breaches, and potential disruption of services, impacting any organization using the affected 54yyyu code-mcp software.

## Recommendation

*   Inspect web server logs for suspicious POST requests to the `git_operation` endpoint in `src/code_mcp/server.py` containing shell command injection attempts, and deploy the `Detect Suspicious Git Operation Requests` Sigma rule.
*   Monitor process creation events for unusual processes spawned by the code-mcp application or related processes, using the `Detect Suspicious Processes Spawned by Code-MCP` Sigma rule.
*   Since no patch is available, consider implementing input validation and sanitization on the `operation` argument within the `git_operation` function or consider isolating the affected service until a patch is released.
