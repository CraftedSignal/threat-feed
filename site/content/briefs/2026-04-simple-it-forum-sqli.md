---
title: Simple IT Discussion Forum SQL Injection Vulnerability (CVE-2026-6004)
slug: 2026-04-simple-it-forum-sqli
description: CVE-2026-6004 is a SQL injection vulnerability in code-projects Simple IT Discussion Forum 1.0's /delete-category.php, allowing remote attackers to execute arbitrary SQL commands by manipulating the cat_id parameter.
date: "2026-04-10T03:19:12Z"
severities:
  - high
tags:
  - sqli
  - cve-2026-6004
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6004
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6004
  - https://vuldb.com/vuln/356560
iocs:
  - type: url
    value: https://nvd.nist.gov
ioc_counts:
  url: 1
rules:
  - title: Detect Suspicious URI Access to delete-category.php
    description: Detects suspicious access to the /delete-category.php file which is vulnerable to SQL injection
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Attempts via URI
    description: Detects potential SQL injection attempts in URI parameters.
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

A SQL injection vulnerability, CVE-2026-6004, has been identified in code-projects Simple IT Discussion Forum version 1.0. The vulnerability resides within the `/delete-category.php` file and stems from improper handling of the `cat_id` argument. A remote attacker can exploit this flaw to inject malicious SQL code, potentially leading to unauthorized data access, modification, or deletion. The vulnerability was published on April 9, 2026, and a public exploit is available, increasing the risk of exploitation. This poses a significant threat to organizations using the affected forum software, as attackers could compromise the integrity and confidentiality of their forum data.

## Attack Chain

1.  The attacker identifies a Simple IT Discussion Forum 1.0 instance exposed to the internet.
2.  The attacker crafts a malicious HTTP request targeting `/delete-category.php`.
3.  The crafted request includes a modified `cat_id` parameter containing SQL injection payload.
4.  The application fails to properly sanitize the `cat_id` input.
5.  The application executes the injected SQL code against the database.
6.  The attacker gains unauthorized access to the database.
7.  The attacker retrieves sensitive information, such as user credentials or forum content.
8.  The attacker modifies or deletes data within the database, causing disruption or further compromise.

## Impact

Successful exploitation of CVE-2026-6004 can lead to complete database compromise, including unauthorized access to sensitive user data, modification or deletion of forum content, and potentially even full control of the web server hosting the application. Given the public availability of the exploit, vulnerable Simple IT Discussion Forum instances are at high risk of being targeted. The exact number of affected installations is unknown, but any organization using version 1.0 of this forum software is susceptible to this attack.

## Recommendation

*   Apply appropriate input validation and sanitization to mitigate the vulnerability in `/delete-category.php` and prevent SQL injection.
*   Deploy the Sigma rule `Detect Suspicious URI Access to delete-category.php` to identify potential exploitation attempts in web server logs.
*   Monitor web server logs for suspicious activity and SQL errors related to the `cat_id` parameter in requests to `/delete-category.php`.
*   Review and restrict database user privileges to minimize the impact of successful SQL injection attacks.
