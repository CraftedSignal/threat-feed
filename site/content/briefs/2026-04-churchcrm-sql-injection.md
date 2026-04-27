---
title: ChurchCRM SQL Injection Vulnerability (CVE-2026-35566)
slug: 2026-04-churchcrm-sql-injection
description: A critical SQL injection vulnerability exists in ChurchCRM versions prior to 7.1.0, stemming from improper validation of the $_SESSION['iCurrentFundraiser'] value in src/Reports/FundRaiserStatement.php, potentially allowing attackers to manipulate database queries.
date: "2026-04-07T16:16:29Z"
severities:
  - critical
tags:
  - sql-injection
  - churchcrm
  - cve-2026-35566
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
cves:
  - id: CVE-2026-35566
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35566
  - https://github.com/ChurchCRM/CRM/security/advisories/GHSA-grq6-q49f-44xh
rules:
  - title: Detect ChurchCRM SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting ChurchCRM's FundRaiserStatement.php
    platform: sigma
    severity: critical
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1505
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Activity in FundRaiserEditor.php
    description: Detects potential suspicious activity in FundRaiserEditor.php related to iCurrentFundraiser parameter
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1505
    data_sources:
      - webserver
      - linux
rules_count: 2
---

ChurchCRM, an open-source church management system, is susceptible to a critical SQL injection vulnerability identified as CVE-2026-35566.  This flaw resides in the `src/Reports/FundRaiserStatement.php` file of versions prior to 7.1.0. The vulnerability arises because the `$_SESSION['iCurrentFundraiser']` value, which originates from `src/FundRaiserEditor.php` is used in an unquoted numeric SQL context without proper integer validation. Specifically, the `InputUtils::legacyFilterInputArr()`…
