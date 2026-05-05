---
title: Oracle MCP Server Helper Tool Unauthenticated SQL Injection Vulnerability (CVE-2026-35228)
slug: 2024-01-oracle-mcp-sqli
description: CVE-2026-35228 is a critical vulnerability in Oracle MCP Server Helper Tool versions 1.0.1 through 1.0.156, allowing unauthenticated remote attackers to execute arbitrary SQL commands.
date: "2024-01-23T18:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - cve
  - web-application
vendors:
  - Oracle
products:
  - MCP Server Helper Tool 1.0.1-1.0.156
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-35228
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35228
rules:
  - title: Detect Suspicious HTTP Requests to MCP Server Helper
    description: Detects HTTP requests that may indicate an SQL injection attempt targeting Oracle MCP Server Helper Tool
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Malicious SQL Execution via MCP Server Helper Tool
    description: Detects suspicious process executions originating from the MCP Server Helper Tool potentially indicative of successful SQL injection
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-35228 is a SQL injection vulnerability affecting the Oracle MCP Server Helper Tool, specifically the 'helper tool' component. The vulnerability exists in versions 1.0.1 through 1.0.156. An unauthenticated attacker with network access via HTTP can exploit this vulnerability, allowing them to execute arbitrary SQL commands on the affected system. This poses a significant risk, as successful exploitation could lead to data breaches, modification of sensitive information, or complete system compromise. Organizations using affected versions of the Oracle MCP Server Helper Tool should take immediate steps to mitigate this risk.

## Attack Chain

1.  The attacker identifies a vulnerable instance of Oracle MCP Server Helper Tool (versions 1.0.1-1.0.156) exposed over HTTP.
2.  The attacker crafts a malicious HTTP request containing a SQL injection payload within a parameter processed by the 'helper tool' component.
3.  The attacker sends the crafted HTTP request to the vulnerable server.
4.  The server-side application fails to properly sanitize the input, passing the malicious SQL payload to the database.
5.  The database executes the attacker-controlled SQL query.
6.  The attacker gains the ability to read, modify, or delete data within the database.
7.  The attacker may escalate their privileges within the application and potentially the underlying operating system.
8.  The attacker achieves their objective, such as exfiltrating sensitive data or disrupting service.

## Impact

Successful exploitation of CVE-2026-35228 allows an unauthenticated attacker to execute arbitrary SQL commands on the Oracle MCP Server Helper Tool. This could lead to the compromise of sensitive data, modification of application settings, or even complete control of the affected server. The severity of the impact depends on the privileges of the database user and the sensitivity of the data stored within the database. If the database user has high privileges, the attacker could potentially take complete control of the system.

## Recommendation

*   Upgrade Oracle MCP Server Helper Tool to a patched version that addresses CVE-2026-35228.
*   Deploy the Sigma rule `Detect Suspicious HTTP Requests to MCP Server Helper` to identify potential exploitation attempts in web server logs.
*   Implement web application firewall (WAF) rules to filter out malicious SQL injection payloads in HTTP requests targeting the MCP Server Helper Tool.
