---
title: mkdocs-mcp-plugin Path Traversal Vulnerability
slug: 2026-04-mkdocs-path-traversal
description: A path traversal vulnerability exists in douinc mkdocs-mcp-plugin up to version 0.4.1, allowing remote attackers to access unauthorized files through manipulation of the docs_dir/file_path argument in the read_document/list_documents functions within server.py.
date: "2026-04-28T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - path-traversal
  - mkdocs
  - CVE-2026-7159
vendors:
  - douinc
products:
  - mkdocs-mcp-plugin (<= 0.4.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7159
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7159
  - https://github.com/douinc/mkdocs-mcp-plugin/
  - https://github.com/douinc/mkdocs-mcp-plugin/issues/6
  - https://vuldb.com/vuln/359758
rules:
  - title: Detect Mkdocs Path Traversal Attempt
    description: Detects potential path traversal attempts targeting mkdocs-mcp-plugin by looking for '../' sequences in the URL.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Mkdocs Directory Listing Traversal
    description: Detects directory listing traversal attempts with '../' sequences in the URL
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

A path traversal vulnerability, identified as CVE-2026-7159, has been discovered in douinc's mkdocs-mcp-plugin, affecting versions up to 0.4.1. The flaw resides within the `read_document` and `list_documents` functions of the `server.py` file. By manipulating the `docs_dir` or `file_path` arguments, a remote attacker can bypass intended access restrictions and potentially read sensitive files on the server. A public exploit is available, increasing the risk of exploitation. The vendor has acknowledged the vulnerability and plans to release a fix in the coming days. This vulnerability poses a significant risk to systems using the affected plugin, potentially exposing sensitive data.

## Attack Chain

1.  Attacker identifies a server running a vulnerable version (<= 0.4.1) of the `mkdocs-mcp-plugin`.
2.  Attacker crafts a malicious HTTP request targeting the `read_document` or `list_documents` endpoint.
3.  The crafted request includes a manipulated `docs_dir` or `file_path` parameter designed to traverse the file system. This commonly involves using sequences like `../` to move up directories.
4.  The vulnerable `server.py` script fails to properly sanitize or validate the provided path.
5.  The application attempts to read a file outside the intended document root, based on the attacker-controlled path.
6.  If successful, the contents of the targeted file are returned in the HTTP response to the attacker.
7.  The attacker can repeat this process to enumerate and access various sensitive files.
8.  The attacker gains unauthorized access to sensitive information, potentially including configuration files, source code, or user data.

## Impact

Successful exploitation of this path traversal vulnerability (CVE-2026-7159) can lead to unauthorized access to sensitive files on the server. This could include configuration files, application source code, or user data. The impact ranges from information disclosure to potential compromise of the entire system, depending on the nature of the exposed data. Given the public availability of an exploit, affected systems are at increased risk of attack. The vendor is planning to release a fix soon.

## Recommendation

*   Apply the patch for mkdocs-mcp-plugin as soon as it is released by the vendor to remediate CVE-2026-7159.
*   Deploy the Sigma rule `Detect Mkdocs Path Traversal Attempt` to identify exploitation attempts in web server logs.
*   Monitor web server logs for suspicious URL patterns containing path traversal sequences like `../` targeting file access endpoints, as detailed in the Attack Chain.
