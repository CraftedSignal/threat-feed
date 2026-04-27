---
title: AlejandroArciniegas mcp-data-vis SQL Injection Vulnerability
slug: 2026-04-mcp-sql-injection
description: A SQL injection vulnerability exists in the MCP Handler component of AlejandroArciniegas mcp-data-vis, specifically in the Request function of src/servers/database/server.js, allowing remote attackers to execute arbitrary SQL commands.
date: "2026-04-02T06:16:23Z"
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve-2026-5322
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5322
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5322
rules:
  - title: Detect SQL Injection Attempts to mcp-data-vis
    description: Detects potential SQL injection attempts targeting the mcp-data-vis application by looking for common SQL syntax in HTTP request URIs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection via POST Request to mcp-data-vis server.js
    description: Detects potential SQL injection attempts targeting the mcp-data-vis application via POST requests that contain SQL syntax in the body, specifically focusing on interaction with server.js.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability has been identified in AlejandroArciniegas's mcp-data-vis project, affecting the MCP Handler component. The vulnerability resides within the `Request` function of the `src/servers/database/server.js` file. This flaw allows a remote attacker to inject arbitrary SQL commands through manipulation of input parameters. Public exploit code is available, increasing the risk of exploitation. Due to the software's rolling release model, identifying specific vulnerable…
