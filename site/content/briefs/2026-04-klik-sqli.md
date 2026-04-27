---
title: KLiK SocialMediaWebsite SQL Injection Vulnerability (CVE-2026-7002)
slug: 2026-04-klik-sqli
description: KLiK SocialMediaWebsite up to version 1.0.1 is vulnerable to SQL injection via manipulation of the c_id argument in the /includes/get_message_ajax.php file, specifically affecting the Private Message Handler component, which can be exploited remotely.
date: "2026-04-26T14:30:00Z"
severities:
  - high
tags:
  - sql-injection
  - vulnerability
  - web-application
vendors:
  - klik
products:
  - SocialMediaWebsite (up to 1.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7002
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7002
  - https://vuldb.com/vuln/359561
  - https://vuldb.com/vuln/359561/cti
rules:
  - title: Detect SQL Injection Attempt in KLiK SocialMediaWebsite
    description: Detects potential SQL injection attempts targeting the /includes/get_message_ajax.php endpoint in KLiK SocialMediaWebsite by looking for SQL keywords in the c_id parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Attempt in KLiK SocialMediaWebsite - Blind SQLi
    description: Detects potential blind SQL injection attempts targeting the /includes/get_message_ajax.php endpoint in KLiK SocialMediaWebsite by looking for time-based SQL keywords in the c_id parameter.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

KLiK SocialMediaWebsite version 1.0.1 and earlier is susceptible to a SQL injection vulnerability (CVE-2026-7002) affecting the Private Message Handler component. This vulnerability resides within the `/includes/get_message_ajax.php` file, and is triggered by manipulating the `c_id` argument. The attack can be launched remotely without authentication, potentially allowing unauthorized access to sensitive data within the application's database. Defenders should prioritize identifying and…
