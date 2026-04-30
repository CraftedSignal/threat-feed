---
title: Kaggle-MCP Path Traversal Vulnerability in prepare_kaggle_dataset Function
slug: 2024-01-kaggle-mcp-path-traversal
description: A path traversal vulnerability exists in the prepare_kaggle_dataset function of kaggle-mcp up to version 406127ffcb2b91b8c10e20e6c2ca787fbc1dc92d, allowing remote attackers to access arbitrary files by manipulating the competition_id argument.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
  - cve
products:
  - kaggle-mcp
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7149
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7149
rules:
  - title: Detect Path Traversal Attempts in HTTP Requests
    description: Detects HTTP requests containing path traversal sequences in the URI query string, potentially indicating an attempt to exploit a path traversal vulnerability.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Abnormal File Access by Web Server
    description: Detects file access events by the web server process that may indicate path traversal or other malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A path traversal vulnerability has been identified in the kaggle-mcp project, specifically affecting versions up to 406127ffcb2b91b8c10e20e6c2ca787fbc1dc92d. The vulnerability resides within the `prepare_kaggle_dataset` function located in the `src/kaggle_mcp/server.py` file.  Successful exploitation allows a remote attacker to read sensitive files from the server. The vulnerability stems from insufficient sanitization of the `competition_id` argument. The exploit is publicly known, increasing the risk of widespread exploitation. The project uses a rolling release model, making it difficult to pinpoint specific affected versions. The maintainers have been notified but have not yet addressed the issue.

## Attack Chain

1. The attacker identifies a vulnerable kaggle-mcp instance.
2. The attacker crafts a malicious HTTP request targeting the endpoint that utilizes the `prepare_kaggle_dataset` function.
3. The attacker injects a path traversal sequence (e.g., `../`) into the `competition_id` parameter of the HTTP request.
4. The application fails to properly sanitize the `competition_id` parameter.
5. The `prepare_kaggle_dataset` function uses the unsanitized `competition_id` to construct a file path.
6. The application accesses a file outside of the intended directory due to the path traversal.
7. The attacker receives the contents of the accessed file in the HTTP response.
8. The attacker repeats this process to enumerate and exfiltrate sensitive files, potentially gaining access to credentials, configuration files, or source code.

## Impact

Successful exploitation of this vulnerability allows an attacker to read arbitrary files on the server hosting the kaggle-mcp application. This can lead to the disclosure of sensitive information, such as configuration files containing database credentials, API keys, or source code. This information can be further leveraged to compromise other systems or data. The number of potential victims is unknown, but depends on the adoption rate of the vulnerable kaggle-mcp application.

## Recommendation

*   Inspect web server logs for HTTP requests containing path traversal sequences (e.g., `../`, `..%2f`) in the `cs-uri-query` field targeting endpoints associated with the `prepare_kaggle_dataset` function using the provided Sigma rule.
*   Implement input validation and sanitization on the `competition_id` parameter to prevent path traversal attacks.
*   Monitor web server logs for unusual file access patterns originating from the kaggle-mcp application based on the provided Sigma rule.
