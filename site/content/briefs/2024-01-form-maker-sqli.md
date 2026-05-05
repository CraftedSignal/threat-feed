---
title: SQL Injection Vulnerability in Form Maker by 10Web WordPress Plugin
slug: 2024-01-form-maker-sqli
description: The Form Maker by 10Web WordPress plugin is vulnerable to SQL Injection via the 'inputs' parameter in versions up to 1.15.42, allowing unauthenticated attackers to extract sensitive information from the database.
date: "2024-01-22T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - wordpress
  - plugin
vendors:
  - 10Web
products:
  - Form Maker by 10Web
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-3359
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3359
rules:
  - title: Detect Form Maker SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the Form Maker by 10Web plugin via the 'inputs' parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Payloads in URI Query
    description: Detects common SQL injection payloads in URI queries.  Useful for broad detection of web application attacks.
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

The Form Maker by 10Web plugin, a WordPress plugin designed for creating mobile-friendly contact forms, is susceptible to SQL Injection attacks. This vulnerability, identified as CVE-2026-3359, affects versions up to and including 1.15.42. The root cause lies in the insufficient escaping of user-supplied input via the 'inputs' parameter and the lack of adequate preparation in the existing SQL query. This flaw enables unauthenticated attackers to inject malicious SQL queries, potentially leading to the extraction of sensitive data from the WordPress database. Successful exploitation allows unauthorized access to potentially sensitive information, impacting the confidentiality of the WordPress site's data.

## Attack Chain

1.  An unauthenticated attacker identifies a WordPress site using a vulnerable version (<= 1.15.42) of the Form Maker by 10Web plugin.
2.  The attacker crafts a malicious HTTP request targeting an endpoint that utilizes the 'inputs' parameter.
3.  The crafted request includes a SQL injection payload within the 'inputs' parameter, designed to bypass input validation.
4.  The WordPress application processes the HTTP request, and the injected SQL code is passed to the database server without proper sanitization.
5.  The database server executes the attacker-supplied SQL code along with the intended query, leading to unintended database operations.
6.  The attacker-controlled SQL query extracts sensitive information, such as user credentials, database structure, or other confidential data.
7.  The extracted data is returned to the attacker as part of the HTTP response, or potentially stored elsewhere for later retrieval.

## Impact

Successful exploitation of this SQL Injection vulnerability can lead to the unauthorized disclosure of sensitive information stored in the WordPress database. This could include user credentials, personal data, or other confidential business information. The impact includes potential data breaches, reputational damage, and legal repercussions. While specific victim counts are unavailable, any WordPress site running a vulnerable version of the plugin is at risk.

## Recommendation

*   Upgrade the Form Maker by 10Web plugin to the latest version to remediate CVE-2026-3359.
*   Deploy the Sigma rule "Detect Form Maker SQL Injection Attempt" to your SIEM to detect potential exploitation attempts targeting the 'inputs' parameter.
*   Monitor web server logs for suspicious requests containing SQL syntax within the 'inputs' parameter to identify and block malicious activity.
