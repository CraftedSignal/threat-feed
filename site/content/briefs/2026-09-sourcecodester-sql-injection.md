---
title: SQL Injection in SourceCodester Online Faculty Clearance System
slug: 2026-09-sourcecodester-sql-injection
description: SourceCodester Online Faculty Clearance System 1.0 is vulnerable to remote SQL injection in /delete_requirement.php via the ID argument, allowing unauthorized database access.
date: "2026-09-15T05:38:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sourcecodester:online_faculty_clearance_system:1.0:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - sql-injection
  - sourcecodester
vendors:
  - SourceCodester
products:
  - Online Faculty Clearance System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument ID leads to sql injection. It is possible to initiate the attack remotely.
    confidence_band: high
cves:
  - id: CVE-2026-90876
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90876
rules:
  - title: Detect CVE-2026-90876 Exploitation - SQL Injection in delete_requirement.php
    description: Detects exploitation attempts against the Online Faculty Clearance System via SQL injection strings in the ID parameter of /delete_requirement.php.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the webserver-based Sigma rule to identify and log exploitation attempts targeting /delete_requirement.php.
      owner: Detection Engineering
      due: 24h
      evidence: Publicly available exploit disclosure.
  mitigation_plan:
    - priority: immediate
      action: Sanitize the ID parameter input and use parameterized SQL queries in the Online Faculty Clearance System 1.0 codebase.
      owner: IT Operations
      addresses: CVE-2026-90876
      evidence: Vulnerability analysis identifies SQL injection in /delete_requirement.php via ID parameter.
---

The SourceCodester Online Faculty Clearance System version 1.0 contains a SQL injection vulnerability within the /delete_requirement.php script. The vulnerability exists due to insufficient sanitization of the ID argument passed during HTTP requests to this endpoint. A remote, unauthenticated attacker can exploit this flaw to inject malicious SQL commands, which are executed directly against the application database. This can lead to unauthorized data retrieval, modification, or potential administrative control over the underlying database. The vulnerability has been confirmed with public exploit availability, increasing the risk of exploitation by opportunistic actors targeting known vulnerabilities in small, publicly available web applications. Defenders should prioritize auditing web server logs for suspicious requests to this specific endpoint and ensure all inputs are properly validated at the application layer.

## Impact

Successful exploitation allows a remote attacker to perform unauthorized database operations, potentially resulting in the compromise of faculty clearance records and personal information stored within the application. Given the nature of SQL injection, this could result in complete data exfiltration, unauthorized deletion of records, or the modification of authentication data.

## Recommendation

1. Deploy web application firewall (WAF) rules to inspect and filter input for SQL syntax characters within the ID parameter of requests to /delete_requirement.php.
2. Implement strict input validation and parameterized queries in the affected PHP source code to neutralize SQL injection vectors.
3. Review web server access logs for anomalous behavior targeting the /delete_requirement.php endpoint, specifically looking for attempts to inject SQL keywords or special characters.
