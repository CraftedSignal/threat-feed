---
title: Path Traversal Vulnerability in WilliamCloudQi matlab-mcp-server
slug: 2024-01-03-matlab-mcp-server-path-traversal
description: A path traversal vulnerability exists in WilliamCloudQi matlab-mcp-server up to version ab88f6b9bf5f36f725e8628029f7f6dd0d9913ca, allowing a remote attacker to manipulate the scriptPath argument in the generate_matlab_code/execute_matlab_code function to access arbitrary files.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-vulnerability
vendors:
  - WilliamCloudQi
products:
  - matlab-mcp-server
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
cves:
  - id: CVE-2026-7272
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7272
rules:
  - title: Detect Path Traversal in matlab-mcp-server via scriptPath
    description: Detects path traversal attempts in the scriptPath parameter of matlab-mcp-server based on common path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Path Traversal in matlab-mcp-server HTTP Request
    description: Detects suspicious HTTP requests to matlab-mcp-server that contain path traversal sequences in the URI.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A path traversal vulnerability, identified as CVE-2026-7272, affects WilliamCloudQi's matlab-mcp-server up to commit ab88f6b9bf5f36f725e8628029f7f6dd0d9913ca. The vulnerability resides within the MCP Interface component, specifically in the `generate_matlab_code/execute_matlab_code` function of the `src/index.ts` file. A remote attacker can exploit this flaw by manipulating the `scriptPath` argument, allowing them to traverse the file system and potentially access sensitive files or execute arbitrary code on the server. This vulnerability is remotely exploitable, and an exploit is publicly available. The vendor was notified but has not yet responded. This poses a significant risk to systems running vulnerable versions of matlab-mcp-server.

## Attack Chain

1.  The attacker identifies a vulnerable instance of WilliamCloudQi matlab-mcp-server running a version up to ab88f6b9bf5f36f725e8628029f7f6dd0d9913ca.
2.  The attacker crafts a malicious HTTP request targeting the `generate_matlab_code` or `execute_matlab_code` function.
3.  The malicious request includes a manipulated `scriptPath` argument containing path traversal sequences (e.g., `../`, `..%2f`).
4.  The server-side code, without proper validation, uses the attacker-controlled `scriptPath` to access a file.
5.  The attacker uses the path traversal to navigate to a sensitive file outside the intended directory (e.g., `/etc/passwd`).
6.  The server reads the contents of the arbitrary file due to the path traversal.
7.  The server includes the contents of the sensitive file in the response sent back to the attacker.
8. The attacker retrieves the sensitive information from the server's response, such as configuration files, credentials, or source code.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to read arbitrary files on the server. This can lead to the disclosure of sensitive information, including configuration files, credentials, source code, or other data stored on the server's file system. This information can then be used for further attacks, such as privilege escalation or lateral movement within the network. The number of potential victims is unknown, but any system running a vulnerable version of matlab-mcp-server is at risk.

## Recommendation

*   Apply appropriate input validation and sanitization to the `scriptPath` argument in the `generate_matlab_code` and `execute_matlab_code` functions to prevent path traversal attacks.
*   Deploy the Sigma rules provided in this brief to your SIEM to detect potential exploitation attempts targeting this vulnerability.
*   Monitor web server logs for suspicious requests containing path traversal sequences (e.g., `../`, `..%2f`) in the `scriptPath` parameter.
