---
title: Pimcore SQL Injection Vulnerability in Custom Reports
slug: 2026-05-pimcore-sqli
description: Pimcore versions up to 12.3.5 are vulnerable to SQL injection via the CustomReportsBundle, allowing an attacker with reports_config permission to execute arbitrary SQL queries and potentially modify database contents.
date: "2026-05-27T00:36:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - pimcore
  - vulnerability
vendors:
  - Pimcore
products:
  - pimcore/pimcore
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
references:
  - https://github.com/advisories/GHSA-3234-gxc3-pq6f
  - CVE-2026-44739
rules:
  - title: Detect Pimcore SQL Injection Attempt via Custom Report Configuration
    description: Detects potential SQL injection attempts targeting the Pimcore Custom Report Configuration endpoint by looking for common SQL injection payloads in the configuration parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Pimcore SQL Injection via Update bypass regex filter
    description: Detects potential SQL injection attempts targeting the Pimcore Custom Report Configuration endpoint and trying to bypass the implemented regex filter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Pimcore, a leading open-source platform for managing digital experiences, is susceptible to SQL injection within its CustomReportsBundle. Disclosed on May 27, 2026, this vulnerability affects versions up to and including 12.3.5. An attacker with the `reports_config` permission can inject malicious SQL code through the `columnConfigAction` endpoint. The application's attempt to filter SQL keywords is insufficient, enabling attackers to bypass the protection mechanism and exfiltrate sensitive information. This vulnerability arises from the direct concatenation of user-supplied input into SQL queries without proper sanitization or parameterization, leading to potential data breaches and unauthorized database modifications. Defenders should prioritize patching to prevent exploitation.

## Attack Chain

1. An attacker authenticates to the Pimcore admin panel with an account possessing the `reports_config` permission.
2. The attacker crafts a malicious JSON payload containing SQL injection code within the `sql`, `from`, or `where` parameters for the custom report configuration.
3. The attacker sends a POST request to the `/admin/bundle/customreports/custom-report/column-config` endpoint with the crafted JSON payload in the `configuration` parameter.
4. The `columnConfigAction` function in `CustomReportController.php` processes the request and extracts the SQL configuration.
5. The `SqlAdapter::buildQueryString` function in `Sql.php` concatenates the attacker-controlled parameters directly into an SQL query string.
6. A weak regular expression is applied to the constructed SQL query in `Sql.php`, but this filter is easily bypassed using techniques like comments or permitted SELECT statements.
7. The unsanitized SQL query is executed using `$db->fetchAssociative($sql)` in `Sql.php` without parameterization.
8. Any database error messages resulting from the injected SQL are returned in the JSON response, enabling error-based data exfiltration. The final objective is to extract sensitive data or potentially modify the database contents, leading to a compromise of data confidentiality, integrity, and availability.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to severe consequences. An attacker can extract sensitive information from the database, including user credentials, configuration details, and business-critical data. Furthermore, attackers can bypass implemented filters to insert, update, or delete database records. This can lead to complete compromise of the application's confidentiality, integrity, and availability. Due to the widespread use of Pimcore in enterprise environments, a successful attack could potentially impact numerous organizations across various sectors.

## Recommendation

*   Upgrade Pimcore to a version greater than 12.3.5 to patch the SQL injection vulnerability in the CustomReportsBundle as outlined in [GHSA-3234-gxc3-pq6f](https://github.com/advisories/GHSA-3234-gxc3-pq6f).
*   Deploy the Sigma rule "Detect Pimcore SQL Injection Attempt via Custom Report Configuration" to identify malicious requests to the `/admin/bundle/customreports/custom-report/column-config` endpoint.
*   Review and harden access controls to the `reports_config` permission, limiting it to only necessary users to minimize the attack surface.
*   Implement parameterized queries and input validation to prevent SQL injection vulnerabilities, addressing the root cause identified in this brief.
