---
title: 54yyyu code-mcp Path Traversal Vulnerability (CVE-2026-7811)
slug: 2024-01-03-code-mcp-path-traversal
description: A path traversal vulnerability exists in the is_safe_path function of the MCP File Handler component in 54yyyu code-mcp, allowing remote attackers to access sensitive files.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
  - CVE-2026-7811
vendors:
  - 54yyyu
products:
  - code-mcp
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-7811
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7811
rules:
  - title: Detect Code-mcp Path Traversal Attempt
    description: Detects attempts to exploit the path traversal vulnerability in 54yyyu code-mcp by identifying requests containing common path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - webserver
      - linux
  - title: Detect Code-mcp Server.py Access with Traversal
    description: Detects access to server.py with directory traversal
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A path traversal vulnerability, identified as CVE-2026-7811, has been discovered in 54yyyu code-mcp, affecting versions up to commit 4cfc4643541a110c906d93635b391bf7e357f4a8. This flaw resides within the `is_safe_path` function in `src/code_mcp/server.py`, a part of the MCP File Handler component. The vulnerability enables remote attackers to bypass security restrictions and potentially access unauthorized files and directories on the server.  The exploit is publicly known. The vendor employs rolling releases, making specific version details unavailable, and has not yet responded to the initial vulnerability report. This lack of response and public exploit availability poses a significant risk to systems running the affected code-mcp versions.

## Attack Chain

1.  The attacker identifies a vulnerable instance of 54yyyu code-mcp running a version with the affected `is_safe_path` function.
2.  The attacker crafts a malicious HTTP request targeting the MCP File Handler, specifically designed to invoke the vulnerable `is_safe_path` function.
3.  The crafted request includes a path containing directory traversal sequences (e.g., `../`) intended to bypass the path validation logic.
4.  The `is_safe_path` function fails to properly sanitize the input path, allowing the traversal sequences to be processed.
5.  The application attempts to access a file or directory outside of the intended base directory based on the attacker-controlled path.
6.  The server reads the contents of the file or directory and includes it in the HTTP response.
7.  The attacker receives the sensitive information, such as configuration files or source code.
8.  The attacker can then use this information to further compromise the system or network.

## Impact

Successful exploitation of this path traversal vulnerability can allow attackers to read sensitive files from the server hosting the 54yyyu code-mcp application. This may include configuration files, source code, or other data that could aid in further attacks, such as privilege escalation or lateral movement. Since the exploit is publicly available, unpatched systems are at immediate risk of compromise. The number of affected installations and the specific sectors impacted are currently unknown, but the potential for data breaches and system compromise is significant.

## Recommendation

*   Deploy the Sigma rule `Detect Code-mcp Path Traversal Attempt` to identify requests containing suspicious path traversal sequences in the `cs-uri-query` field of web server logs.
*   Enable web server logging to capture HTTP requests and responses, which is required for the Sigma rule to function correctly (logsource: `webserver`).
*   Since specific patched versions are unavailable due to the rolling release model, monitor the vendor's code repository for updates to the `is_safe_path` function in `src/code_mcp/server.py` and deploy the updated code as soon as it becomes available.
*   Implement a web application firewall (WAF) rule to block requests containing path traversal sequences like `../` in URL parameters to mitigate the risk proactively.
