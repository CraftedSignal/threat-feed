---
title: code-projects Vehicle Showroom Management System 1.0 SQL Injection Vulnerability
slug: 2024-01-15-vehicle-showroom-sql-injection
description: A remote SQL injection vulnerability exists in code-projects Vehicle Showroom Management System 1.0 via manipulation of the BRANCH_ID argument in the /util/BookVehicleFunction.php file, potentially allowing unauthorized database access.
date: "2024-01-15T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-6149
  - sql-injection
  - web-application
vendors:
  - code-projects
products:
  - Vehicle Showroom Management System
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6149
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6149
  - https://vuldb.com/vuln/357029
rules:
  - title: Detect Suspicious BookVehicleFunction.php Access
    description: Detects suspicious access to the BookVehicleFunction.php file, potentially indicating SQL injection attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Characters in URI Query
    description: Detects common SQL injection characters in the URI query string, potentially indicating an attack.
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

A SQL injection vulnerability has been identified in code-projects Vehicle Showroom Management System version 1.0. This vulnerability, tracked as CVE-2026-6149, resides within the `/util/BookVehicleFunction.php` file. Successful exploitation allows remote attackers to inject malicious SQL code by manipulating the `BRANCH_ID` argument. Publicly available exploit code exists, increasing the risk of widespread exploitation. This vulnerability poses a significant threat to organizations using the affected software, potentially leading to data breaches, unauthorized access, and complete system compromise.

## Attack Chain

1.  The attacker identifies an instance of code-projects Vehicle Showroom Management System 1.0.
2.  The attacker crafts a malicious HTTP request targeting `/util/BookVehicleFunction.php`.
3.  The attacker injects SQL code into the `BRANCH_ID` parameter within the HTTP request.
4.  The web server passes the crafted SQL query to the underlying database without proper sanitization.
5.  The database executes the malicious SQL query.
6.  The attacker extracts sensitive information from the database.
7.  The attacker may use the extracted credentials to gain further access to the system.
8.  The attacker can modify, delete, or exfiltrate data from the database, leading to complete system compromise.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-6149) can have severe consequences. An attacker can gain unauthorized access to the Vehicle Showroom Management System's database, potentially exposing sensitive customer data, vehicle inventory information, and financial records. The vulnerability could lead to data breaches, financial losses, and reputational damage. Given the nature of the application, dealerships and other businesses managing vehicle inventories are the most likely targets.

## Recommendation

*   Apply the Sigma rule `Detect Suspicious BookVehicleFunction.php Access` to identify potential exploitation attempts targeting the vulnerable endpoint.
*   Inspect web server logs for unusual requests to `/util/BookVehicleFunction.php` with suspicious characters or SQL keywords in the `BRANCH_ID` parameter.
*   Patch CVE-2026-6149 immediately upon patch availability to mitigate the SQL injection vulnerability.
*   Implement proper input validation and sanitization on the `BRANCH_ID` parameter in `/util/BookVehicleFunction.php` to prevent future SQL injection attacks.
