---
title: Pimcore Admin Classic Bundle SQL Injection Vulnerability in Translation Grid Date Filter
slug: 2026-05-pimcore-sqli
description: The Pimcore admin-ui-classic-bundle is vulnerable to SQL injection via the translation grid date filter; the user-supplied `property` field from the filter JSON is interpolated directly into a SQL expression without proper sanitization or validation, potentially leading to arbitrary database data extraction and remote code execution when chained with other vulnerabilities.
date: "2026-05-27T00:37:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pimcore:pimcore:*:*:*:*:*:*:*:*
tags:
  - sql-injection
  - pimcore
  - cve-2026-44741
  - web-application
vendors:
  - Pimcore
products:
  - admin-ui-classic-bundle (<= 2.3.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-27461
    cvss: 4.9
    epss: 0.00013
references:
  - https://github.com/advisories/GHSA-h4ph-crvj-9h92
  - CVE-2026-27461
rules:
  - title: Detect CVE-2026-44741 Exploitation Attempt — Pimcore Translation Grid SQL Injection
    description: Detects CVE-2026-44741 exploitation attempts — HTTP POST requests to /admin/translation/translations with SQL injection attempts in the filter parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-44741 Exploitation Attempt — Pimcore Translation Grid SQL Injection (Comment Bypass)
    description: Detects CVE-2026-44741 exploitation attempts — HTTP POST requests to /admin/translation/translations with SQL injection attempts in the filter parameter using comment bypass techniques.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The `pimcore/admin-ui-classic-bundle` version 2.3.5 and earlier contains an SQL injection vulnerability within the translation grid's date filter functionality. This flaw arises because the `property` parameter, supplied by a user through a JSON filter, is incorporated directly into a SQL expression without sufficient sanitization or validation. Specifically, the `str_replace('--', '')` sanitization applied is easily bypassed, allowing malicious SQL code to be injected. Successful exploitation allows an authenticated user with the necessary permissions to extract sensitive information from the database. Furthermore, when combined with another vulnerability (GM-249, an unsafe unserialize), it can lead to remote code execution.

## Attack Chain

1. An attacker authenticates to the Pimcore application with translation view permissions.
2. The attacker crafts a malicious POST request to `/admin/translation/translations` with a JSON payload containing a `date` type filter.
3. The `property` field in the filter is manipulated to contain SQL injection payloads, such as `1))) UNION SELECT password FROM users WHERE ((1`.
4. The application's `src/Controller/Admin/TranslationController.php` processes the request, extracting the malicious `property` value at line 565.
5. The inadequate sanitization `str_replace('--', '', $fieldname)` at line 569 is bypassed using techniques like comment injection (`/**/`) or redundant dashes (`----`).
6. At line 593, the unsanitized `$fieldname` is interpolated into a SQL expression: `UNIX_TIMESTAMP(DATE(FROM_UNIXTIME({$fieldname})))`.
7. The application executes the crafted SQL query against the database.
8. The attacker receives the results of the SQL injection, potentially including sensitive data. Chaining with GM-249 allows for RCE.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-44741) can lead to unauthorized data extraction from the Pimcore database by an attacker with translation view permissions. The combination of this SQL injection with the GM-249 unsafe unserialize vulnerability can lead to full remote code execution. The vulnerability affects `pimcore/admin-ui-classic-bundle` version 2.3.5 and earlier.

## Recommendation

*   Apply the vendor-supplied patch or upgrade to a version of `pimcore/admin-ui-classic-bundle` greater than 2.3.5 to remediate CVE-2026-44741.
*   Implement input validation on the `property` field in the translation grid date filter to only allow expected column names, as suggested in the provided fix (see "Suggested Fix" section in content).
*   Deploy the Sigma rule "Detect CVE-2026-44741 Exploitation Attempt — Pimcore Translation Grid SQL Injection" to detect potential exploitation attempts (see "rules" section).
*   Monitor web server logs for POST requests to `/admin/translation/translations` with suspicious characters or SQL syntax in the `filter` parameter.
