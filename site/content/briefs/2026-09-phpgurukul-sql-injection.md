---
title: SQL Injection in PHPGurukul Daily Expense Tracker System
slug: 2026-09-phpgurukul-sql-injection
description: An unauthenticated SQL injection vulnerability in the login component of PHPGurukul Daily Expense Tracker System 1.1 allows remote attackers to execute arbitrary database queries.
date: "2026-09-15T01:37:51Z"
lastmod: "2026-09-15T01:38:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:phpgurukul:daily_expense_tracker_system:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - sql-injection
  - cve-2026-90844
vendors:
  - PHPGurukul
products:
  - Daily Expense Tracker System (1.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote exploitation of the attack is possible.
    confidence_band: high
cves:
  - id: CVE-2026-90844
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90844
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90846
rules:
  - title: Detects CVE-2026-90844 Exploitation - SQL Injection via Login Endpoint
    description: Detects potential SQL injection attempts targeting the email parameter in the Daily Expense Tracker System login page.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-90846 Exploitation - SQL Injection in forgot-password.php
    description: Detects exploitation attempts targeting CVE-2026-90846 by monitoring for SQL injection syntax in the email or contactno parameters of the forgot-password.php script
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block or inspect traffic targeting /dets/index.php with anomalous email parameters
      owner: SOC
      due: 24h
      evidence: CVE-2026-90844 vulnerability details
  mitigation_plan:
    - priority: immediate
      action: Patch PHPGurukul Daily Expense Tracker System to the latest secure version
      owner: IT Operations
      addresses: CVE-2026-90844
      evidence: NVD vulnerability disclosure
updates:
  - at: "2026-09-15T01:38:00Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-90846 Exploitation - SQL Injection in forgot-password.php'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-90846
---

PHPGurukul Daily Expense Tracker System version 1.1 contains a SQL injection vulnerability within the login component. The vulnerability is located in the '/dets/index.php' file, where the 'email' parameter fails to properly sanitize user-supplied input before passing it to database queries. An unauthenticated remote attacker can supply crafted SQL payloads via the email argument to manipulate back-end queries. This allows for unauthorized data access, potential authentication bypass, or administrative compromise of the underlying database. The vulnerability has been publicly disclosed and is considered exploitable by remote actors. Defenses should focus on monitoring HTTP requests to the identified login endpoint for signs of SQL injection patterns.

## Impact

Successful exploitation allows an unauthenticated attacker to interact directly with the application database, potentially resulting in the exfiltration of user credentials, financial records, or system configuration data. In high-privilege scenarios, this may facilitate a full compromise of the application server.

## Recommendation

Prioritize remediation by updating or patching the PHPGurukul Daily Expense Tracker System to a version that addresses CVE-2026-90844. As the component is vulnerable to SQL injection, ensure that all input handling in 'index.php' utilizes prepared statements or parameterized queries.
