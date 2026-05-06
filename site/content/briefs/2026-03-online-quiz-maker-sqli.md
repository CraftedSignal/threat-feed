---
title: Online Quiz Maker 1.0 SQL Injection Vulnerability (CVE-2018-25207)
slug: 2026-03-online-quiz-maker-sqli
description: Online Quiz Maker 1.0 is vulnerable to SQL injection via the catid and usern parameters, allowing authenticated attackers to execute arbitrary SQL commands by submitting malicious POST requests to quiz-system.php or add-category.php.
date: "2026-03-26T12:16:05Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - cve-2018-25207
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25207
  - https://www.exploit-db.com/exploits/45323
  - https://www.hscripts.com/scripts/php/downloads/quiz-maker.zip
  - https://www.hscripts.com/scripts/php/quiz-maker.php
  - https://www.vulncheck.com/advisories/online-quiz-maker-sql-injection-via-catid-parameter
rules:
  - title: SQL Injection in Online Quiz Maker
    description: Detects potential SQL injection attempts in Online Quiz Maker via POST requests to quiz-system.php or add-category.php
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detecting SQL Injection Attempts via URI Containing Common SQL Keywords
    description: Detects SQL injection attempts by looking for common SQL keywords in the URI.
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

Online Quiz Maker 1.0 is susceptible to SQL injection vulnerabilities, specifically identified as CVE-2018-25207. The vulnerability resides in the `catid` and `usern` parameters, which can be exploited by an authenticated attacker to inject arbitrary SQL commands. The attack vector involves crafting malicious POST requests to either `quiz-system.php` or `add-category.php`. Successful exploitation of this vulnerability can lead to unauthorized access to sensitive data stored in the database…
