---
title: Simple IT Discussion Forum 1.0 SQL Injection Vulnerability (CVE-2026-5672)
slug: 2024-01-simple-it-forum-sql-injection
description: A remote SQL injection vulnerability exists in code-projects Simple IT Discussion Forum 1.0 via manipulation of the cat_id parameter in the /edit-category.php file.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - vulnerability
vendors:
  - code-projects
products:
  - Simple IT Discussion Forum
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5672
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5672
  - https://code-projects.org/
  - https://github.com/Czhan1156/Czhan/issues/1
  - https://vuldb.com/submit/792389
  - https://vuldb.com/vuln/355500
  - https://vuldb.com/vuln/355500/cti
rules:
  - title: Detect Suspicious cat_id Parameter in edit-category.php
    description: Detects potential SQL injection attempts by monitoring the cat_id parameter in requests to /edit-category.php.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1211
    data_sources:
      - webserver
      - linux
  - title: Detect edit-category.php POST Request with Potential SQL Injection Payloads
    description: Detects POST requests to edit-category.php containing potential SQL injection attempts.
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

A SQL injection vulnerability, identified as CVE-2026-5672, has been discovered in code-projects Simple IT Discussion Forum version 1.0. The vulnerability resides within the `/edit-category.php` file, specifically in the Parameter Handler component. This allows unauthenticated remote attackers to inject arbitrary SQL commands by manipulating the `cat_id` parameter. Public exploits for this vulnerability are available, potentially increasing the risk of widespread exploitation. Successful exploitation could allow attackers to read, modify, or delete sensitive data within the forum's database, potentially leading to complete compromise of the application and its underlying infrastructure.

## Attack Chain

1.  An attacker identifies a vulnerable Simple IT Discussion Forum 1.0 instance exposed to the internet.
2.  The attacker crafts a malicious HTTP request targeting the `/edit-category.php` endpoint.
3.  The attacker injects SQL code into the `cat_id` parameter within the request's query string or POST data.
4.  The webserver processes the request and passes the tainted `cat_id` value to the application's database query.
5.  Due to the lack of proper input sanitization, the injected SQL code is executed by the database server.
6.  The attacker can then extract sensitive data, such as user credentials or configuration details, from the database.
7.  The attacker may further manipulate the database to escalate privileges, modify content, or inject malicious code into the application.
8.  Ultimately, the attacker achieves complete control over the application and potentially the underlying server.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-5672) can lead to unauthorized access to sensitive information, data modification, or complete system compromise. Since Simple IT Discussion Forum 1.0 is used by various organizations for online discussions, a successful attack could result in data breaches, defacement of the forum, or further attacks on connected systems. The vulnerability has a CVSS v3.1 score of 7.3 (HIGH), indicating a significant risk.

## Recommendation

*   Apply input validation and sanitization to the `cat_id` parameter in `/edit-category.php` to prevent SQL injection.
*   Upgrade to a patched version of Simple IT Discussion Forum that addresses CVE-2026-5672 (if available).
*   Deploy the Sigma rule `Detect Suspicious cat_id Parameter in edit-category.php` to identify exploitation attempts in web server logs.
*   Implement a web application firewall (WAF) rule to block requests containing SQL injection payloads targeting `/edit-category.php`.
*   Monitor web server logs for suspicious activity related to SQL injection attempts, focusing on requests to `/edit-category.php`.
