---
title: MLOps_MCP Path Traversal Vulnerability (CVE-2026-7213)
slug: 2024-01-mlops-mcp-path-traversal
description: A path traversal vulnerability exists in ef10007 MLOps_MCP version 1.0.0, allowing a remote attacker to manipulate the 'filename/destination' argument in the 'save_file Tool' component's 'fastmcp_server.py' file.
date: "2024-01-02T12:00:00Z"
severities:
  - high
tags:
  - path-traversal
  - web-application
  - cve-2026-7213
vendors:
  - ef10007
products:
  - MLOps_MCP 1.0.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7213
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7213
rules:
  - title: Detect MLOps_MCP Path Traversal Attempt
    description: Detects path traversal attempts targeting fastmcp_server.py via HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Web Server Path Traversal
    description: Detects generic path traversal attempts in web server logs.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A path traversal vulnerability, identified as CVE-2026-7213, has been discovered in ef10007 MLOps_MCP version 1.0.0. The vulnerability resides within the `fastmcp_server.py` file of the `save_file Tool` component. It allows a remote attacker to perform path traversal by manipulating the `filename/destination` argument. The existence of a public exploit increases the risk of exploitation. The vendor has been notified but has not yet responded, leaving users vulnerable to potential attacks. This…
