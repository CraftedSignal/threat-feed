---
title: AlejandroArciniegas mcp-data-vis SQL Injection Vulnerability
slug: 2026-04-mcp-sql-injection
description: A SQL injection vulnerability exists in the MCP Handler component of AlejandroArciniegas mcp-data-vis, specifically in the Request function of src/servers/database/server.js, allowing remote attackers to execute arbitrary SQL commands.
date: "2026-04-02T06:16:23Z"
type: advisory
types:
  - advisory
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

A SQL injection vulnerability has been identified in AlejandroArciniegas's mcp-data-vis project, affecting the MCP Handler component. The vulnerability resides within the `Request` function of the `src/servers/database/server.js` file. This flaw allows a remote attacker to inject arbitrary SQL commands through manipulation of input parameters. Public exploit code is available, increasing the risk of exploitation. Due to the software's rolling release model, identifying specific vulnerable versions is challenging. The vendor was notified but did not respond to the disclosure, potentially delaying remediation efforts and increasing the window of opportunity for malicious actors to exploit this vulnerability.

## Attack Chain

1.  Attacker identifies a publicly accessible instance of mcp-data-vis.
2.  The attacker analyzes the `src/servers/database/server.js` file to understand the structure of the `Request` function.
3.  The attacker crafts a malicious SQL injection payload targeting the `Request` function.
4.  The attacker sends a specially crafted HTTP request containing the SQL injection payload to the vulnerable endpoint.
5.  The vulnerable `Request` function processes the malicious SQL query without proper sanitization.
6.  The injected SQL code is executed against the backend database, potentially allowing data extraction.
7.  The attacker retrieves sensitive data from the database, such as user credentials or application configuration.
8.  The attacker could potentially use the compromised database to pivot to other systems within the network, or deface the web application.

## Impact

Successful exploitation of this SQL injection vulnerability could lead to unauthorized access to sensitive data, including user credentials and application configurations. The lack of versioning information due to the rolling release model makes it difficult to identify and patch vulnerable instances. Organizations using mcp-data-vis are at risk of data breaches, service disruption, and potential compromise of their entire infrastructure if this vulnerability is exploited. Given the public availability of exploit code, the likelihood of exploitation is high, particularly for unpatched systems.

## Recommendation

*   Inspect and sanitize all user-provided input passed to the `Request` function in `src/servers/database/server.js` within the mcp-data-vis application to prevent SQL injection.
*   Deploy the provided Sigma rule to detect suspicious network activity indicative of SQL injection attempts targeting the `Request` function.
*   Monitor web server logs for suspicious HTTP requests containing potentially malicious SQL syntax related to CVE-2026-5322.
*   Implement a Web Application Firewall (WAF) with rules to block common SQL injection payloads targeting the mcp-data-vis application.
