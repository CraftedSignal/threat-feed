---
title: Easy Blog Site SQL Injection Vulnerability (CVE-2026-5805)
slug: 2026-04-easy-blog-sql-injection
description: A SQL injection vulnerability (CVE-2026-5805) exists in code-projects Easy Blog Site up to version 1.0, allowing remote attackers to manipulate the 'Name' argument in the /users/contact_us.php file for unauthorized database access.
date: "2026-04-08T21:17:02Z"
severities:
  - high
exploited: true
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
  - id: CVE-2026-5805
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5805
  - https://code-projects.org/
  - https://github.com/ahmadmarz10-hub/CVEsMarz/blob/main/SQL%20Injection%20in%20Easy%20Blog%20Site%20PHP%20name%20Parameter.md
  - https://vuldb.com/submit/787031
  - https://vuldb.com/vuln/356243
  - https://vuldb.com/vuln/356243/cti
rules:
  - title: Detect SQL Injection Attempt in Easy Blog Site Contact Form
    description: Detects potential SQL injection attempts targeting the /users/contact_us.php file in Easy Blog Site by looking for suspicious characters and SQL keywords in the request.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Error Messages
    description: Detects SQL injection attempts based on SQL error messages in the web server logs.
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

A SQL injection vulnerability, identified as CVE-2026-5805, affects code-projects Easy Blog Site versions up to 1.0. The vulnerability resides in the `/users/contact_us.php` file and can be exploited by manipulating the `Name` argument. This allows a remote attacker to inject malicious SQL queries, potentially leading to unauthorized access to the database, data modification, or even complete system compromise. The availability of a public exploit increases the risk of active exploitation…
