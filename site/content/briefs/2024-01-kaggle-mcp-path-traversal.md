---
title: Kaggle-MCP Path Traversal Vulnerability in prepare_kaggle_dataset Function
slug: 2024-01-kaggle-mcp-path-traversal
description: A path traversal vulnerability exists in the prepare_kaggle_dataset function of kaggle-mcp up to version 406127ffcb2b91b8c10e20e6c2ca787fbc1dc92d, allowing remote attackers to access arbitrary files by manipulating the competition_id argument.
date: "2024-01-09T10:00:00Z"
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

A path traversal vulnerability has been identified in the kaggle-mcp project, specifically affecting versions up to 406127ffcb2b91b8c10e20e6c2ca787fbc1dc92d. The vulnerability resides within the `prepare_kaggle_dataset` function located in the `src/kaggle_mcp/server.py` file.  Successful exploitation allows a remote attacker to read sensitive files from the server. The vulnerability stems from insufficient sanitization of the `competition_id` argument. The exploit is publicly known, increasing…
