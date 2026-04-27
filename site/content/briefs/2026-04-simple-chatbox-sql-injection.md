---
title: Simple ChatBox Unauthenticated SQL Injection Vulnerability (CVE-2026-6161)
slug: 2026-04-simple-chatbox-sql-injection
description: CVE-2026-6161 is an unauthenticated SQL injection vulnerability in the Simple ChatBox application (<= 1.0) that can be exploited by sending a crafted HTTP request to `/chatbox/insert.php`.
date: "2026-04-13T05:16:05Z"
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve-2026-6161
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6161
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6161
  - https://code-projects.org/
  - https://github.com/ahmadmarz10-hub/CVEsMarz/blob/main/SQL%20Injection%20in%20Simple%20Chatbox%20PHP%20msg%20Parameter.md
  - https://vuldb.com/vuln/357041
rules:
  - title: Detect Simple Chatbox SQL Injection Attempt
    description: Detects potential SQL injection attempts in the Simple Chatbox application by looking for common SQL injection keywords in the msg parameter of requests to insert.php
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
  - title: Detect Simple Chatbox SQL Injection via POST Data
    description: Detects potential SQL injection attempts in the Simple Chatbox application by looking for common SQL injection keywords in the body of POST requests to insert.php.
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
rules_count: 2
---

A critical SQL injection vulnerability, identified as CVE-2026-6161, has been discovered in Simple ChatBox version 1.0 and earlier. This flaw resides in the `/chatbox/insert.php` file, which is responsible for handling chat message insertion. A remote attacker can exploit this vulnerability by injecting malicious SQL code into the `msg` parameter of an HTTP request, without needing authentication. The attacker's malicious SQL commands are then executed against the application database. The…
