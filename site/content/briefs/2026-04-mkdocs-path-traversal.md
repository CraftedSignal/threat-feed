---
title: mkdocs-mcp-plugin Path Traversal Vulnerability
slug: 2026-04-mkdocs-path-traversal
description: A path traversal vulnerability exists in douinc mkdocs-mcp-plugin up to version 0.4.1, allowing remote attackers to access unauthorized files through manipulation of the docs_dir/file_path argument in the read_document/list_documents functions within server.py.
date: "2026-04-28T12:00:00Z"
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

A path traversal vulnerability, identified as CVE-2026-7159, has been discovered in douinc's mkdocs-mcp-plugin, affecting versions up to 0.4.1. The flaw resides within the `read_document` and `list_documents` functions of the `server.py` file. By manipulating the `docs_dir` or `file_path` arguments, a remote attacker can bypass intended access restrictions and potentially read sensitive files on the server. A public exploit is available, increasing the risk of exploitation. The vendor has…
