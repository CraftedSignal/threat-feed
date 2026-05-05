---
title: Axle-Bucamp MCP-Docusaurus Path Traversal Vulnerability
slug: 2026-05-mcp-docusaurus-path-traversal
description: A path traversal vulnerability exists in Axle-Bucamp MCP-Docusaurus versions up to commit 404bc028e15ec304c9a045528560f4b5f27a17e0, allowing remote attackers to access sensitive files by manipulating the DOCS_DIR/path argument in specific functions.
date: "2026-05-05T00:16:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - vulnerability
  - web-application
vendors:
  - Axle-Bucamp
products:
  - MCP-Docusaurus
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7788
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7788
rules:
  - title: Detect MCP-Docusaurus Path Traversal Attempt
    description: Detects attempts to exploit the path traversal vulnerability in MCP-Docusaurus by looking for '../' sequences in the request URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect MCP-Docusaurus Path Traversal via Encoded Characters
    description: Detects attempts to exploit the path traversal vulnerability in MCP-Docusaurus by looking for encoded '../' sequences in the request URI.
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

A path traversal vulnerability has been identified in Axle-Bucamp MCP-Docusaurus, affecting versions up to commit 404bc028e15ec304c9a045528560f4b5f27a17e0. The vulnerability resides within the `update_document`, `continue_document`, `delete_document`, and `get_content` functions of the `app/routes/document.py` file. By manipulating the `DOCS_DIR/path` argument, a remote attacker can gain unauthorized access to sensitive files on the server. The exploit is publicly available, increasing the risk of exploitation. The vendor employs a rolling release model, making it difficult to pinpoint specific affected versions, and has not yet responded to vulnerability reports. This vulnerability poses a significant threat to the confidentiality of data managed by MCP-Docusaurus.

## Attack Chain

1.  The attacker identifies an MCP-Docusaurus instance running a vulnerable version (<= 404bc028e15ec304c9a045528560f4b5f27a17e0).
2.  The attacker crafts a malicious HTTP request targeting the `update_document`, `continue_document`, `delete_document`, or `get_content` functions in `app/routes/document.py`.
3.  The crafted request includes a modified `DOCS_DIR/path` argument containing path traversal sequences (e.g., `../`, `../../`).
4.  The MCP-Docusaurus application processes the malicious request without proper validation of the `path` argument.
5.  The application constructs a file path using the attacker-controlled `path` argument, resulting in access to files outside the intended `DOCS_DIR` directory.
6.  The attacker successfully reads, modifies, or deletes arbitrary files on the server, depending on the function targeted and server permissions.
7.  The attacker may escalate their access by retrieving sensitive configuration files containing credentials.
8.  The attacker leverages compromised credentials to gain further access to the system or network.

## Impact

Successful exploitation of this path traversal vulnerability allows attackers to read sensitive files, potentially including configuration files, source code, and user data. Depending on the permissions of the application, attackers may also be able to modify or delete files, leading to data corruption or denial of service. Given the public availability of the exploit, organizations using vulnerable versions of MCP-Docusaurus are at high risk of compromise. The lack of vendor response further exacerbates the risk.

## Recommendation

*   Monitor web server logs for suspicious requests containing path traversal sequences (`../`, `../../`) in the URI, specifically targeting `app/routes/document.py` (see example Sigma rule below).
*   Implement input validation and sanitization for the `DOCS_DIR/path` argument in the `update_document`, `continue_document`, `delete_document`, and `get_content` functions.
*   Since specific version information is unavailable, prioritize upgrading to the latest version of MCP-Docusaurus as soon as a patch is released.
*   Audit access control configurations to limit the application's access to only necessary files and directories.
