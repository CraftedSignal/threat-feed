---
title: code-projects Online FIR System SQL Injection Vulnerability
slug: 2026-04-online-fir-sqli
description: A SQL injection vulnerability in code-projects Online FIR System 1.0 allows remote attackers to execute arbitrary SQL commands by manipulating the email or password parameters in the /Login/checklogin.php file.
date: "2026-04-06T16:16:41Z"
severities:
  - high
tags:
  - sqli
  - cve-2026-5665
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-5665
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5665
  - https://code-projects.org/
  - https://github.com/ahmadmarz10-hub/CVEsMarz/blob/main/SQL%20Injection%20in%20Online%20FIR%20System%20PHP%20email%20Parameter.md
  - https://vuldb.com/submit/786310
  - https://vuldb.com/vuln/355488
  - https://vuldb.com/vuln/355488/cti
ioc_counts:
  email: 1
  url: 5
rules:
  - title: Detect SQL Injection Attempts in Online FIR System Login
    description: Detects potential SQL injection attempts targeting the /Login/checklogin.php endpoint by searching for common SQL injection keywords in the email or password parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Exploitation of code-projects Online FIR System SQL Injection
    description: Detects possible exploitation of the SQL Injection vulnerability in code-projects Online FIR System 1.0
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

A SQL injection vulnerability has been identified in code-projects Online FIR System version 1.0. The vulnerability resides within the `/Login/checklogin.php` file, specifically affecting the login component. An attacker can remotely exploit this vulnerability by manipulating the `email` or `password` parameters within a request. The vulnerability has been assigned CVE-2026-5665 and given a CVSS v3.1 score of 7.3, indicating a high severity. Public exploits exist, meaning defenders should…
