---
title: eiceblue spire-doc-mcp-server Path Traversal Vulnerability
slug: 2026-04-spire-doc-mcp-server-path-traversal
description: A path traversal vulnerability exists in eiceblue spire-doc-mcp-server version 1.0.0, allowing a remote attacker to access arbitrary files by manipulating the 'document_name' argument in the 'get_doc_path' function.
date: "2026-04-29T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - path-traversal
  - web-application
  - cve-2026-7314
vendors:
  - eiceblue
products:
  - spire-doc-mcp-server 1.0.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7314
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7314
  - https://github.com/eiceblue/spire-doc-mcp-server/
  - https://github.com/eiceblue/spire-doc-mcp-server/issues/1
  - https://vuldb.com/submit/803080
  - https://vuldb.com/vuln/359962
  - https://vuldb.com/vuln/359962/cti
rules:
  - title: Detect Spire-doc-mcp-server Path Traversal Attempt
    description: Detects path traversal attempts in requests to spire-doc-mcp-server by looking for common path traversal sequences in the URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Spire-doc-mcp-server Base64 Encoded Path Traversal Attempt
    description: Detects base64 encoded path traversal attempts in requests to spire-doc-mcp-server by looking for base64 encoded path traversal sequences in the URI.
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

A critical path traversal vulnerability has been identified in eiceblue spire-doc-mcp-server version 1.0.0. The vulnerability resides within the `get_doc_path` function of the `src/spire_doc_mcp/api/base.py` file. By manipulating the `document_name` argument, an attacker can bypass intended directory restrictions and access files outside the designated document path. This attack can be initiated remotely without authentication, posing a significant risk. Public exploits are available, increasing the likelihood of exploitation. The vendor was notified through an issue report, but has not yet responded.

## Attack Chain

1.  The attacker sends a crafted HTTP request to the spire-doc-mcp-server.
2.  The request targets an endpoint that utilizes the vulnerable `get_doc_path` function.
3.  The attacker manipulates the `document_name` parameter within the request.
4.  The `document_name` parameter contains a path traversal sequence (e.g., "../") designed to escape the intended directory.
5.  The `get_doc_path` function fails to properly sanitize or validate the `document_name` input.
6.  The application constructs a file path based on the malicious input.
7.  The application attempts to read the file at the attacker-controlled path.
8.  The attacker successfully retrieves the contents of an arbitrary file on the server.

## Impact

Successful exploitation of this path traversal vulnerability allows an attacker to read sensitive files on the server. This could include configuration files containing credentials, source code, or other confidential data. The CVSS v3.1 score of 7.3 reflects the high severity of this issue. The lack of vendor response and availability of public exploits significantly increases the risk to organizations using vulnerable versions of spire-doc-mcp-server.

## Recommendation

*   Deploy the Sigma rule `Detect Spire-doc-mcp-server Path Traversal Attempt` to your SIEM to detect exploitation attempts by monitoring web server logs for path traversal sequences.
*   Apply input validation and sanitization to the `document_name` argument in the `get_doc_path` function within `src/spire_doc_mcp/api/base.py` to prevent path traversal.
*   Monitor web server logs for HTTP requests containing path traversal sequences (e.g., "..%2F", "../") targeting endpoints related to document retrieval.
