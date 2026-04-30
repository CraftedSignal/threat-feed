---
title: Eiceblue Spire-PDF-MCP-Server Path Traversal Vulnerability (CVE-2026-7315)
slug: 2026-04-spire-pdf-path-traversal
description: A path traversal vulnerability exists in eiceblue spire-pdf-mcp-server version 0.1.1, allowing remote attackers to access arbitrary files via manipulation of the filepath argument in the get_pdf_path function.
date: "2026-04-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
  - cve
vendors:
  - eiceblue
products:
  - spire-pdf-mcp-server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7315
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7315
  - https://github.com/eiceblue/spire-pdf-mcp-server/
  - https://github.com/eiceblue/spire-pdf-mcp-server/issues/1
  - https://vuldb.com/vuln/359963
rules:
  - title: Detect Spire-PDF Path Traversal Attempt
    description: Detects attempts to exploit the path traversal vulnerability (CVE-2026-7315) in eiceblue spire-pdf-mcp-server by detecting path traversal sequences in the filepath parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Spire-PDF Path Traversal in POST Data
    description: Detects attempts to exploit the path traversal vulnerability (CVE-2026-7315) in eiceblue spire-pdf-mcp-server through POST request data.
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

A path traversal vulnerability, identified as CVE-2026-7315, affects eiceblue spire-pdf-mcp-server version 0.1.1. The vulnerability resides in the `get_pdf_path` function within the `src/spire_pdf_mcp/server.py` file. By manipulating the `filepath` argument, a remote attacker can bypass directory traversal restrictions and potentially access sensitive files on the server. Public exploits are available, increasing the risk of exploitation. The vendor has been notified but has not yet provided a patch or response. This vulnerability poses a significant risk to systems running the affected software.

## Attack Chain

1.  The attacker identifies a vulnerable instance of eiceblue spire-pdf-mcp-server 0.1.1 exposed to the network.
2.  The attacker crafts a malicious HTTP request targeting the `get_pdf_path` function, embedding a path traversal sequence (e.g., `../`) within the `filepath` parameter.
3.  The server receives the request and processes the `filepath` argument without proper sanitization or validation.
4.  The `get_pdf_path` function constructs a file path using the attacker-controlled input, allowing the traversal of directories outside the intended PDF file storage location.
5.  The server attempts to access a file outside the intended directory, based on the manipulated path.
6.  If successful, the server reads the contents of the arbitrary file.
7.  The server returns the contents of the file to the attacker.
8.  The attacker gains unauthorized access to sensitive information, potentially including configuration files, credentials, or other confidential data.

## Impact

Successful exploitation of CVE-2026-7315 allows a remote attacker to read arbitrary files on the server. This can lead to the disclosure of sensitive information, such as configuration files, credentials, or internal application code. The impact could include complete compromise of the affected system and potential lateral movement within the network. Given the availability of public exploits, the risk of widespread exploitation is elevated.

## Recommendation

*   Deploy the Sigma rule `Detect Spire-PDF Path Traversal Attempt` to identify malicious requests containing path traversal sequences.
*   Monitor web server logs for HTTP requests targeting the `get_pdf_path` function with suspicious `filepath` parameters (e.g., containing "../").
*   Implement strict input validation and sanitization measures for the `filepath` argument in the `get_pdf_path` function to prevent path traversal attacks.
*   Apply any available patches or updates from the vendor as soon as they are released to address CVE-2026-7315.
