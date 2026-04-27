---
title: Media Library Assistant WordPress Plugin SQL Injection Vulnerability
slug: 2026-04-mla-sql-injection
description: The Media Library Assistant WordPress plugin through version 3.34 is vulnerable to SQL injection, allowing attackers to manipulate database queries.
date: "2026-04-06T15:17:11Z"
severities:
  - high
tags:
  - sql-injection
  - wordpress
  - plugin-vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34885
    cvss: 8.5
    epss: 0.06168
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34885
  - https://patchstack.com/database/wordpress/plugin/media-library-assistant/vulnerability/wordpress-media-library-assistant-plugin-3-34-sql-injection-vulnerability?_s_id=cve
rules:
  - title: Detect SQL Injection Attempts via HTTP Request
    description: Detects potential SQL injection attempts based on common SQL keywords in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection in POST requests
    description: Detects potential SQL injection attempts based on common SQL keywords in POST requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-34885 describes an SQL Injection vulnerability affecting the Media Library Assistant WordPress plugin. This plugin, developed by David Lingren, is vulnerable in versions up to and including 3.34. The vulnerability stems from improper neutralization of special elements used in SQL commands, potentially allowing attackers to inject malicious SQL code. Exploitation could lead to unauthorized data access, modification, or deletion within the WordPress database. Given the widespread use of…
