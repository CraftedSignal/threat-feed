---
title: ChurchCRM SQL Injection Vulnerability in PropertyTypeEditor.php
slug: 2024-01-29-churchcrm-sqli
description: A critical SQL injection vulnerability (CVE-2026-39323) in ChurchCRM versions prior to 7.1.0 allows authenticated users with 'Manage Properties' permission to execute arbitrary SQL commands via unsanitized POST parameters in PropertyTypeEditor.php, leading to potential data exfiltration, modification, or deletion.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - churchcrm
  - sql-injection
  - web-application
vendors:
  - ChurchCRM
products:
  - ChurchCRM
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-39323
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39323
rules:
  - title: Detect ChurchCRM SQL Injection Attempt via PropertyTypeEditor.php
    description: Detects potential SQL injection attempts in ChurchCRM's PropertyTypeEditor.php by identifying suspicious characters in the POST request body.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect ChurchCRM SQL Injection via base64 encoded payload
    description: Detects potential SQL injection attempts in ChurchCRM's PropertyTypeEditor.php with base64 encoded payload.
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

ChurchCRM, an open-source church management system, is vulnerable to SQL injection in versions prior to 7.1.0. The vulnerability, identified as CVE-2026-39323, resides in the PropertyTypeEditor.php component. The root cause is the insufficient sanitization of the Name and Description POST parameters. These parameters are only processed with `strip_tags()` before being directly concatenated into SQL queries. An authenticated user with "Manage Properties" permission can exploit this by injecting malicious SQL code through these parameters. Successful exploitation allows the attacker to execute arbitrary SQL commands, giving them the ability to exfiltrate sensitive data, modify existing records, or delete critical information from the database. The injected data persists in the database and is reflected across multiple application pages without proper output encoding, amplifying the impact. Users of ChurchCRM are advised to upgrade to version 7.1.0 or later to remediate this vulnerability.

## Attack Chain

1. An attacker authenticates to the ChurchCRM application with an account that has the "Manage Properties" permission.
2. The attacker crafts a malicious HTTP POST request targeting `PropertyTypeEditor.php`.
3. The POST request includes SQL injection payloads within the `Name` and/or `Description` parameters.
4. The `PropertyTypeEditor.php` script receives the POST request and applies `strip_tags()` to the `Name` and `Description` parameters.
5. The sanitized, but still vulnerable, `Name` and `Description` parameters are concatenated directly into an SQL query without proper escaping or parameterization.
6. The malicious SQL query is executed against the ChurchCRM database.
7. The attacker gains the ability to manipulate database records, potentially exfiltrating sensitive data like user credentials, financial records, or personal information.
8. The injected data persists in the database and gets reflected in other application pages, further compromising the application's integrity.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-39323) in ChurchCRM can lead to severe consequences. An attacker can gain unauthorized access to sensitive data, including member information, financial records, and user credentials. The attacker could modify or delete critical data, disrupting church operations and potentially leading to financial losses. The number of organizations potentially affected is significant, as ChurchCRM is a widely used open-source solution for church management. The injected data will persist in the database and is reflected across multiple application pages without output encoding.

## Recommendation

*   Upgrade ChurchCRM to version 7.1.0 or later to patch the SQL injection vulnerability (CVE-2026-39323).
*   Implement input validation and parameterized queries to prevent SQL injection attacks in `PropertyTypeEditor.php` and other database interaction points within ChurchCRM.
*   Deploy the Sigma rule to detect potential exploitation attempts targeting `PropertyTypeEditor.php`.
*   Review web server access logs for suspicious POST requests to `PropertyTypeEditor.php` (webserver log source).
