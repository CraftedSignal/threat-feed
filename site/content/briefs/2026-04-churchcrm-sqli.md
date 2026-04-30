---
title: ChurchCRM SQL Injection Vulnerability (CVE-2026-35567)
slug: 2026-04-churchcrm-sqli
description: ChurchCRM versions prior to 7.1.0 are vulnerable to SQL injection via the NewRole POST parameter, allowing authenticated users with the ManageGroups role to execute arbitrary SQL commands.
date: "2026-04-07T16:16:29Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-35567
  - sql-injection
  - churchcrm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-35567
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35567
  - https://github.com/ChurchCRM/CRM/security/advisories/GHSA-5f97-jgg4-gqwr
iocs:
  - type: url
    value: https://github.com/ChurchCRM/CRM/security/advisories/GHSA-5f97-jgg4-gqwr
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
  url: 1
rules:
  - title: Detect Suspicious POST Requests to MemberRoleChange.php with SQL Injection Patterns
    description: Detects POST requests to MemberRoleChange.php with SQL injection patterns in the NewRole parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Authentication Attempts with SQL Injection Payloads
    description: Detects authentication attempts to ChurchCRM with SQL injection payloads in login parameters.
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

ChurchCRM, an open-source church management system, is susceptible to SQL injection attacks in versions prior to 7.1.0. The vulnerability, identified as CVE-2026-35567, resides in the `src/MemberRoleChange.php` file, specifically within the `NewRole` POST parameter. Exploitation requires an attacker to have an authenticated session with the `ManageGroups` role, along with knowledge of valid `GroupID` and `PersonID` values, which can be obtained from the `GroupView` or `PersonView` pages. Successful exploitation can lead to unauthorized data access, modification, or deletion within the ChurchCRM database. The vulnerability is resolved in ChurchCRM version 7.1.0.

## Attack Chain

1.  Attacker gains authenticated access to ChurchCRM with a user account possessing the `ManageGroups` role.
2.  Attacker identifies valid `GroupID` and `PersonID` values by browsing the `GroupView` or `PersonView` pages.
3.  Attacker crafts a malicious HTTP POST request targeting `src/MemberRoleChange.php`.
4.  The POST request includes the `NewRole` parameter containing a crafted SQL injection payload, exploiting the lack of proper integer validation.
5.  The application executes the SQL query incorporating the injected payload.
6.  The attacker retrieves sensitive data from the database, modifies existing data, or injects malicious data.
7.  The attacker could leverage the SQL injection to create a new administrative user.
8.  The attacker uses the new administrative account to take complete control of the ChurchCRM instance.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-35567) in ChurchCRM can result in the complete compromise of the application's database. An attacker can gain unauthorized access to sensitive church member data, including personally identifiable information (PII). This can lead to data breaches, identity theft, and financial fraud. Malicious actors could also modify or delete data, disrupting church operations and potentially causing reputational damage. The impact is critical, especially considering the sensitive nature of the data managed by ChurchCRM.

## Recommendation

*   Upgrade ChurchCRM installations to version 7.1.0 or later to remediate the SQL injection vulnerability (CVE-2026-35567).
*   Deploy the provided Sigma rule to detect suspicious POST requests to `src/MemberRoleChange.php` containing potential SQL injection attempts.
*   Monitor web server logs for unusual activity related to `MemberRoleChange.php`, especially concerning the `NewRole` parameter (webserver log source).
*   Implement input validation and sanitization measures for all user-supplied data, focusing on integer validation for parameters like `NewRole`.
