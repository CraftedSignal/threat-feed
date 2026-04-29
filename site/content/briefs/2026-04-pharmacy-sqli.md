---
title: SourceCodester Pharmacy Sales and Inventory System SQL Injection Vulnerability
slug: 2026-04-pharmacy-sqli
description: SourceCodester Pharmacy Sales and Inventory System 1.0 is vulnerable to SQL injection via the ID parameter in the /ajax.php?action=save_type endpoint, allowing remote attackers to execute arbitrary SQL commands.
date: "2026-04-27T14:16:56Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - sqli
  - vulnerability
  - web-application
vendors:
  - SourceCodester
products:
  - Pharmacy Sales and Inventory System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-7128
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7128
  - https://github.com/lonelyuan/vunls/issues/13
  - https://vuldb.com/vuln/359727
rules:
  - title: Detect SQL Injection Attempt in Pharmacy Sales System
    description: Detects potential SQL injection attempts targeting the /ajax.php endpoint by looking for specific SQL keywords in the query string.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Vulnerable AJAX Endpoint
    description: This rule detects access to the specific vulnerable endpoint in SourceCodester Pharmacy Sales and Inventory System.
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

A SQL injection vulnerability has been identified in SourceCodester Pharmacy Sales and Inventory System version 1.0. The vulnerability resides in the `/ajax.php?action=save_type` endpoint and is triggered by manipulating the `ID` argument. Successful exploitation allows a remote attacker to inject and execute arbitrary SQL commands within the application's database. Publicly available exploits exist, increasing the likelihood of exploitation. This vulnerability poses a significant risk to organizations using the affected software, potentially leading to data breaches, data manipulation, or complete system compromise.

## Attack Chain

1.  The attacker identifies a vulnerable instance of SourceCodester Pharmacy Sales and Inventory System 1.0.
2.  The attacker crafts a malicious HTTP request targeting the `/ajax.php?action=save_type` endpoint.
3.  The request includes a manipulated `ID` parameter containing a SQL injection payload.
4.  The application fails to properly sanitize the `ID` parameter before using it in a SQL query.
5.  The malicious SQL payload is executed against the application's database.
6.  The attacker may extract sensitive data from the database, such as user credentials or financial records.
7.  The attacker may modify data within the database, potentially altering inventory levels or pricing information.
8.  The attacker could potentially gain complete control over the database server, leading to full system compromise.

## Impact

Successful exploitation of this SQL injection vulnerability could lead to unauthorized access to sensitive customer data, financial records, and proprietary business information. An attacker could potentially modify or delete data, disrupt business operations, and compromise the entire system. While specific victim numbers are unknown, any organization using SourceCodester Pharmacy Sales and Inventory System 1.0 is potentially at risk. The CVSS v3.1 score of 7.3 indicates a high level of severity.

## Recommendation

*   Apply input validation and sanitization to the `ID` parameter in the `/ajax.php?action=save_type` endpoint to prevent SQL injection attacks.
*   Deploy the Sigma rule provided below to detect suspicious requests targeting the vulnerable endpoint.
*   Monitor web server logs for unusual activity and SQL-related errors, referencing the file path `/ajax.php?action=save_type`.
*   Upgrade to a patched version of SourceCodester Pharmacy Sales and Inventory System once available.
