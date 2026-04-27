---
title: ChurchCRM SQL Injection Vulnerability (CVE-2026-35567)
slug: 2026-04-churchcrm-sqli
description: ChurchCRM versions prior to 7.1.0 are vulnerable to SQL injection via the NewRole POST parameter, allowing authenticated users with the ManageGroups role to execute arbitrary SQL commands.
date: "2026-04-07T16:16:29Z"
severities:
  - high
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

ChurchCRM, an open-source church management system, is susceptible to SQL injection attacks in versions prior to 7.1.0. The vulnerability, identified as CVE-2026-35567, resides in the `src/MemberRoleChange.php` file, specifically within the `NewRole` POST parameter. Exploitation requires an attacker to have an authenticated session with the `ManageGroups` role, along with knowledge of valid `GroupID` and `PersonID` values, which can be obtained from the `GroupView` or `PersonView` pages…
