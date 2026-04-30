---
title: code-projects Student Membership System SQL Injection Vulnerability (CVE-2026-5195)
slug: 2026-04-student-membership-sql-injection
description: A remote SQL injection vulnerability exists in the User Registration Handler component of code-projects Student Membership System 1.0, exploitable through manipulation of input.
date: "2026-03-31T09:18:57Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - web-application
  - cve-2026-5195
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5195
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5195
  - https://vuldb.com/vuln/354293
rules:
  - title: Detect SQL Injection Attempts in User Registration
    description: Detects suspicious HTTP requests to the User Registration page with potential SQL injection payloads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection via common injection strings
    description: Detects SQL injection attacks by identifying common SQL injection strings in HTTP requests
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability, identified as CVE-2026-5195, has been discovered in code-projects Student Membership System version 1.0. The vulnerability specifically affects the "User Registration Handler" component. An attacker can remotely exploit this flaw by manipulating input to execute arbitrary SQL queries. This vulnerability could allow an attacker to read, modify, or delete sensitive data within the application's database. The base CVSS v3.1 score is 7.3, indicating a high severity…
