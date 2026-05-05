---
title: Path Traversal Vulnerability in UsamaK98 python-notebook-mcp
slug: 2026-05-python-notebook-mcp-path-traversal
description: A path traversal vulnerability exists in the create_notebook/read_notebook/edit_cell/add_cell functions of server.py in UsamaK98's python-notebook-mcp, allowing remote attackers to access arbitrary files.
date: "2026-05-05T04:16:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path traversal
  - vulnerability
  - python-notebook-mcp
vendors:
  - UsamaK98
products:
  - python-notebook-mcp
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7810
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7810
rules:
  - title: Detect Python-Notebook-MCP Path Traversal in create_notebook
    description: Detects path traversal attempts in the create_notebook function of python-notebook-mcp.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Python-Notebook-MCP Path Traversal in read_notebook
    description: Detects path traversal attempts in the read_notebook function of python-notebook-mcp.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Python-Notebook-MCP Path Traversal in edit_cell or add_cell
    description: Detects path traversal attempts in the edit_cell or add_cell functions of python-notebook-mcp.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 3
---

A path traversal vulnerability, identified as CVE-2026-7810, affects the UsamaK98 python-notebook-mcp project. The vulnerability resides within the create_notebook, read_notebook, edit_cell, and add_cell functions of the server.py file. An unauthenticated remote attacker can exploit this flaw to read or write arbitrary files on the server. The project uses a rolling release model, making specific version identification difficult. While the vulnerability was reported to the project maintainers, there has been no response as of this writing. This vulnerability is remotely exploitable and can lead to significant data exposure or server compromise.

## Attack Chain

1.  Attacker identifies a vulnerable python-notebook-mcp instance exposed to the internet.
2.  Attacker crafts a malicious HTTP request targeting the create_notebook endpoint.
3.  The crafted request includes a path traversal sequence (e.g., "../") within the filename parameter, designed to escape the intended directory.
4.  The server.py script processes the request without proper sanitization of the filename.
5.  The create_notebook function attempts to create a file outside of the intended notebook directory.
6.  The attacker then uses read_notebook to read the file that they created to verify successful path traversal.
7.  The attacker crafts further requests to read sensitive files on the server, such as configuration files or user data.
8.  The attacker gains unauthorized access to sensitive information, potentially leading to account compromise or further system exploitation.

## Impact

Successful exploitation of this path traversal vulnerability (CVE-2026-7810) allows an attacker to read and potentially create or modify arbitrary files on the server hosting the python-notebook-mcp application. Given the nature of notebook applications, this could expose sensitive code, data, or credentials stored within the application's environment. The lack of specific version details due to the rolling release model makes patching and mitigation challenging for users.

## Recommendation

*   Deploy the Sigma rule `Detect Python-Notebook-MCP Path Traversal in create_notebook` to identify exploitation attempts targeting the create_notebook function.
*   Deploy the Sigma rule `Detect Python-Notebook-MCP Path Traversal in read_notebook` to identify exploitation attempts targeting the read_notebook function.
*   Monitor web server logs for HTTP requests containing path traversal sequences (e.g., "../", "..\", "%2e%2e/") in the URI, especially those targeting the create_notebook, read_notebook, edit_cell, and add_cell functions as described in the overview.
