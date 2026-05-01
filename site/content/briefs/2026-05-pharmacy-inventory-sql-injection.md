---
title: SourceCodester Pharmacy Sales and Inventory System SQL Injection Vulnerability
slug: 2026-05-pharmacy-inventory-sql-injection
description: CVE-2026-7550 is an SQL injection vulnerability in SourceCodester Pharmacy Sales and Inventory System 1.0, allowing remote attackers to execute arbitrary SQL commands by manipulating the ID argument in the /ajax.php?action=save_customer endpoint.
date: "2026-05-01T05:16:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve-2026-7550
vendors:
  - SourceCodester
products:
  - Pharmacy Sales and Inventory System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7550
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7550
  - https://github.com/khairulazly760530-cell/cves/issues/2
  - https://vuldb.com/vuln/360360
rules:
  - title: Detect SQL Injection Attempt in Pharmacy Inventory System
    description: Detects potential SQL injection attempts targeting the /ajax.php endpoint by analyzing the cs-uri-query field for suspicious SQL syntax.
    platform: sigma
    severity: high
    tactics:
      - injection
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Attempt in Pharmacy Inventory System - POST Method
    description: Detects potential SQL injection attempts targeting the /ajax.php endpoint using POST method by analyzing the POST request body for suspicious SQL syntax.
    platform: sigma
    severity: high
    tactics:
      - injection
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

SourceCodester Pharmacy Sales and Inventory System 1.0 is vulnerable to SQL injection via the /ajax.php?action=save_customer endpoint. Disclosed on May 1, 2026, the vulnerability, identified as CVE-2026-7550, allows unauthenticated remote attackers to inject arbitrary SQL commands by manipulating the `ID` argument. The vulnerability exists due to insufficient input validation. Public exploit code is available, increasing the risk of exploitation. This vulnerability allows attackers to potentially read, modify, or delete sensitive data within the application's database.

## Attack Chain

1.  The attacker identifies the vulnerable endpoint `/ajax.php?action=save_customer` within the Pharmacy Sales and Inventory System 1.0 application.
2.  The attacker crafts a malicious HTTP GET or POST request targeting the `/ajax.php?action=save_customer` endpoint.
3.  The crafted request includes a manipulated `ID` parameter designed to inject SQL commands.
4.  The application fails to properly sanitize the input provided in the `ID` parameter.
5.  The application executes the attacker-supplied SQL code against the database.
6.  The attacker can retrieve sensitive information, such as customer details, product information, or administrative credentials.
7.  The attacker may modify existing data, such as prices or inventory levels.
8.  The attacker may gain complete control of the database, potentially leading to full system compromise.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-7550) can lead to unauthorized access to sensitive data, data modification, or complete database compromise. This could result in financial losses, reputational damage, and legal repercussions for affected organizations. Given the nature of the application, attackers could potentially access patient data or prescription information, leading to severe privacy breaches.

## Recommendation

*   Apply input validation and sanitization to the `ID` parameter in the `/ajax.php?action=save_customer` endpoint to prevent SQL injection attacks.
*   Monitor web server logs for suspicious requests targeting the `/ajax.php?action=save_customer` endpoint with unusual `ID` parameter values. Deploy the provided Sigma rule to detect potential exploitation attempts.
*   Consider using a Web Application Firewall (WAF) to filter out malicious requests targeting this vulnerability.
*   Upgrade to a patched version of the SourceCodester Pharmacy Sales and Inventory System once available.
*   Implement regular database backups to mitigate potential data loss due to successful exploitation.
