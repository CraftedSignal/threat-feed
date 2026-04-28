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

ChurchCRM, an open-source church management system, is susceptible to a critical SQL injection vulnerability identified as CVE-2026-35566.  This flaw resides in the `src/Reports/FundRaiserStatement.php` file of versions prior to 7.1.0. The vulnerability arises because the `$_SESSION['iCurrentFundraiser']` value, which originates from `src/FundRaiserEditor.php` is used in an unquoted numeric SQL context without proper integer validation. Specifically, the `InputUtils::legacyFilterInputArr()` function is called without the `'int'` type specifier, failing to sanitize user-supplied input effectively. Successful exploitation could allow an attacker to execute arbitrary SQL queries, potentially leading to unauthorized data access, modification, or deletion. The vulnerability has been addressed in ChurchCRM version 7.1.0.

## Attack Chain

1. A low-privileged attacker authenticates to the ChurchCRM application.
2. The attacker navigates to the `src/FundRaiserEditor.php` page.
3. The attacker manipulates the `$_SESSION['iCurrentFundraiser']` parameter, injecting a malicious SQL payload. This is done by sending a crafted request to the server.
4. The `InputUtils::legacyFilterInputArr()` function processes the tainted `$_SESSION['iCurrentFundraiser']` value without proper sanitization due to the missing `'int'` type specifier.
5. The unsanitized value is then passed to the `src/Reports/FundRaiserStatement.php` script.
6. `src/Reports/FundRaiserStatement.php` incorporates the malicious SQL payload into an unquoted numeric SQL context.
7. The database executes the attacker-controlled SQL query, potentially leaking sensitive data, modifying existing records, or even executing database commands.
8. The attacker gains unauthorized access to or control over the ChurchCRM database.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-35566) can have severe consequences. An attacker could potentially read sensitive data such as personal information of church members, financial records, and internal communications.  Furthermore, they could modify or delete critical data, leading to data breaches, financial losses, and reputational damage. The exact number of vulnerable installations and potential victims is unknown, but any organization running ChurchCRM versions prior to 7.1.0 is at risk.

## Recommendation

*   Upgrade ChurchCRM to version 7.1.0 or later to patch CVE-2026-35566.
*   Implement input validation and sanitization measures on all user-supplied data, especially when constructing SQL queries.  Pay special attention to the use of `InputUtils::legacyFilterInputArr()` and ensure the `'int'` type specifier is used where appropriate.
*   Deploy the Sigma rule `Detect ChurchCRM SQL Injection Attempt` to monitor web server logs for suspicious requests targeting `src/Reports/FundRaiserStatement.php`.
*   Conduct regular security audits and penetration testing of ChurchCRM installations to identify and remediate potential vulnerabilities.
