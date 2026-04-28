---
title: Elinsky execution-system-mcp Path Traversal Vulnerability
slug: 2026-04-elinsky-path-traversal
description: Elinsky execution-system-mcp 0.1.0 is vulnerable to path traversal via manipulation of the context argument in the _get_context_file_path function, allowing remote attackers to access sensitive files.
date: "2026-04-29T10:00:00Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - path-traversal
  - web-application
  - cve-2026-7319
vendors:
  - elinsky
products:
  - execution-system-mcp 0.1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7319
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7319
  - https://github.com/elinsky/execution-system-mcp/
  - https://github.com/elinsky/execution-system-mcp/issues/1
  - https://vuldb.com/submit/803085
  - https://vuldb.com/vuln/359972
  - https://vuldb.com/vuln/359972/cti
rules:
  - title: Detect Path Traversal in elinsky execution-system-mcp
    description: Detects path traversal attempts in HTTP requests targeting the add_action tool of elinsky execution-system-mcp by looking for common path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Path Traversal via get_context_file_path function
    description: Detects path traversal attempts by identifying requests that specifically target the vulnerable function get_context_file_path.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A path traversal vulnerability, identified as CVE-2026-7319, affects elinsky execution-system-mcp version 0.1.0. The vulnerability resides in the `_get_context_file_path` function located within the `src/execution_system_mcp/server.py` file, which is part of the `add_action` Tool component. By manipulating the `context` argument, a remote attacker can bypass directory restrictions and access unauthorized files. The existence of a published exploit increases the risk of this vulnerability being actively exploited. Defenders should prioritize patching and implementing mitigations to prevent potential data breaches or system compromise.

## Attack Chain

1.  The attacker identifies a vulnerable instance of elinsky execution-system-mcp 0.1.0 running remotely.
2.  The attacker crafts a malicious HTTP request targeting the `add_action` tool.
3.  Within the HTTP request, the attacker injects a path traversal sequence (e.g., `../`) into the `context` argument of the `_get_context_file_path` function.
4.  The `_get_context_file_path` function processes the tainted input without proper sanitization, allowing the path traversal sequence to resolve to a file outside of the intended directory.
5.  The server attempts to read the file specified by the attacker-controlled path.
6.  Sensitive information from the targeted file is read by the server.
7.  The server returns the content of the file, or an error message indicating the file content, to the attacker.
8.  The attacker obtains sensitive information, potentially leading to further exploitation, such as privilege escalation or data exfiltration.

## Impact

Successful exploitation of this vulnerability allows an attacker to read arbitrary files on the server. This could lead to the disclosure of sensitive information, such as configuration files, source code, or user data. The CVSS v3.1 score of 7.3 indicates a high severity, highlighting the potential for significant impact. The lack of specifics regarding victim count and sectors targeted in the source information makes it difficult to quantify the precise scale of potential damage.

## Recommendation

*   Apply any available patches or updates for elinsky execution-system-mcp to address CVE-2026-7319.
*   Implement input validation and sanitization measures to prevent path traversal attacks within the `_get_context_file_path` function.
*   Deploy the Sigma rule provided to detect exploitation attempts by monitoring for suspicious path traversal sequences in HTTP requests to the `add_action` tool.
*   Monitor web server logs for requests containing path traversal sequences such as "../" and ensure proper logging of access attempts.
