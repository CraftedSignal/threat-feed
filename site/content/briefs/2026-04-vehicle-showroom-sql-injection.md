---
title: Vehicle Showroom Management System SQL Injection Vulnerability (CVE-2026-6152)
slug: 2026-04-vehicle-showroom-sql-injection
description: A remote SQL injection vulnerability exists in code-projects Vehicle Showroom Management System 1.0 due to improper handling of the STAFF_ID parameter in /util/StaffAddingFunction.php, potentially allowing attackers to execute arbitrary SQL commands.
date: "2026-04-13T03:16:03Z"
severities:
  - high
tags:
  - sql-injection
  - web-application
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6152
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6152
  - https://code-projects.org/
  - https://github.com/zheng-lv/CVE-/issues/3
  - https://vuldb.com/vuln/357032
rules:
  - title: Detect SQL Injection Attempt in Vehicle Showroom Management System
    description: Detects potential SQL injection attempts targeting the /util/StaffAddingFunction.php file in Vehicle Showroom Management System via the STAFF_ID parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Exploitation via GitHub Public Exploit URL
    description: Detects requests coming from GitHub to the vehicle showroom exploit code.
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

CVE-2026-6152 details a critical SQL injection vulnerability within version 1.0 of the code-projects Vehicle Showroom Management System. The flaw resides in the `/util/StaffAddingFunction.php` file and is triggered by manipulating the `STAFF_ID` parameter. Publicly disclosed exploits exist, meaning unauthenticated remote attackers can leverage this vulnerability to inject malicious SQL queries into the application's database. Successful exploitation could lead to unauthorized data access, modification, or deletion, compromising the integrity and confidentiality of the Vehicle Showroom Management System. This is especially concerning given the sensitive information typically stored within such systems, including customer data, vehicle inventory, and financial records. Defenders need to prioritize patching or implementing mitigations to prevent potential exploitation.

## Attack Chain

1.  An attacker identifies an instance of Vehicle Showroom Management System 1.0 exposed to the internet.
2.  The attacker crafts a malicious HTTP request targeting `/util/StaffAddingFunction.php`.
3.  The crafted request includes a manipulated `STAFF_ID` parameter containing SQL injection payload.
4.  The application fails to properly sanitize the `STAFF_ID` input.
5.  The unsanitized input is incorporated into a SQL query executed by the application.
6.  The injected SQL code is executed by the database server.
7.  The attacker gains unauthorized access to sensitive data stored within the database, potentially including user credentials, financial information, or vehicle details.
8.  The attacker exfiltrates sensitive data or modifies database records to further compromise the system.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-6152) in Vehicle Showroom Management System 1.0 allows unauthenticated remote attackers to execute arbitrary SQL queries. This can lead to the theft of sensitive customer data, modification of vehicle inventory records, or complete compromise of the application and its underlying database. The impact ranges from data breaches and financial losses to reputational damage. Given the publicly available exploit code, organizations using the vulnerable software are at significant risk of attack. The number of potential victims is unknown, but any organization using Vehicle Showroom Management System 1.0 is vulnerable.

## Recommendation

*   Apply any available patches or updates for Vehicle Showroom Management System 1.0 from code-projects to remediate CVE-2026-6152.
*   Implement input validation and sanitization measures on the `/util/StaffAddingFunction.php` file, specifically for the `STAFF_ID` parameter, to prevent SQL injection attacks.
*   Deploy the provided Sigma rule to detect exploitation attempts targeting `/util/StaffAddingFunction.php` based on suspicious characters in the STAFF_ID parameter.
*   Monitor web server logs for unusual activity, specifically requests to `/util/StaffAddingFunction.php` with suspicious characters in the `STAFF_ID` parameter.
*   Consider using a web application firewall (WAF) to filter malicious requests targeting this vulnerability and block requests matching the patterns identified in the Sigma rules.
