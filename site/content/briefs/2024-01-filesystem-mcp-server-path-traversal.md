---
title: geekgod382 filesystem-mcp-server Path Traversal Vulnerability (CVE-2026-7400)
slug: 2024-01-filesystem-mcp-server-path-traversal
description: A path traversal vulnerability exists in geekgod382 filesystem-mcp-server version 1.0.0 allowing remote attackers to access unauthorized files due to insufficient path validation in the is_path_allowed function.
date: "2024-01-02T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - path-traversal
  - web-application
  - cve-2026-7400
products:
  - filesystem-mcp-server
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1553
    technique_name: Subvert Trust Relationship
cves:
  - id: CVE-2026-7400
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7400
rules:
  - title: filesystem-mcp-server Path Traversal Attempt
    description: Detects potential path traversal attempts targeting filesystem-mcp-server by looking for common path traversal sequences in request URIs.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1553.005
    data_sources:
      - webserver
      - linux
  - title: filesystem-mcp-server Malicious File Access
    description: Detects potential access to sensitive files via path traversal by monitoring the file names accessed.
    platform: sigma
    severity: critical
    tactics:
      - resource_development
    techniques:
      - T1553.005
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical path traversal vulnerability, identified as CVE-2026-7400, affects geekgod382 filesystem-mcp-server version 1.0.0. This vulnerability resides within the `is_path_allowed` function in the `server.py` file, specifically in the `read_file_tool/write_file_tool` component. A remote attacker can exploit this weakness to bypass intended access restrictions and potentially read or write sensitive files outside the designated directories. Publicly available exploit code exists, increasing the urgency for remediation. Upgrade to version 1.1.0 to apply the patch (45364545fc60dc80aadcd4379f08042d3d3d292e) and mitigate this risk. This vulnerability allows attackers to potentially gain unauthorized access to the underlying system.

## Attack Chain

1.  The attacker identifies a vulnerable instance of `filesystem-mcp-server` version 1.0.0 exposed to the network.
2.  The attacker crafts a malicious request targeting the `read_file_tool` or `write_file_tool` component.
3.  The crafted request includes a path traversal sequence (e.g., `../`) within the file path parameter.
4.  The `is_path_allowed` function fails to properly sanitize the input path, allowing the traversal sequence to bypass intended restrictions.
5.  The application processes the request, accessing a file outside the intended directory.
6.  If using `read_file_tool`, the contents of the unauthorized file are returned to the attacker.
7.  If using `write_file_tool`, the attacker can overwrite legitimate files, potentially injecting malicious code.
8.  Successful exploitation allows the attacker to read sensitive information or achieve arbitrary code execution on the server.

## Impact

Successful exploitation of this path traversal vulnerability (CVE-2026-7400) can allow an attacker to read arbitrary files from the affected server, potentially exposing sensitive data such as configuration files, credentials, or internal documents. If the write_file_tool is exploited, the attacker might overwrite critical system files, leading to denial of service or arbitrary code execution. This issue affects systems running geekgod382 filesystem-mcp-server version 1.0.0.

## Recommendation

*   Upgrade to geekgod382 filesystem-mcp-server version 1.1.0 to apply the patch (45364545fc60dc80aadcd4379f08042d3d3d292e) that fixes CVE-2026-7400.
*   Deploy the Sigma rule "filesystem-mcp-server Path Traversal Attempt" to detect potential exploitation attempts against the filesystem-mcp-server.
*   Monitor web server logs for suspicious requests containing path traversal sequences (`../`, `..\\`) targeting file access endpoints, as this may indicate exploitation attempts.
*   Implement input validation and sanitization measures to prevent path traversal attacks, even after upgrading, as defense-in-depth.
