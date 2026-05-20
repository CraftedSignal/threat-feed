---
title: Creative Mail WordPress Plugin Vulnerable to SQL Injection (CVE-2026-3985)
slug: 2026-05-creative-mail-sqli
description: The Creative Mail plugin for WordPress is vulnerable to SQL Injection due to insufficient escaping of the 'checkout_uuid' parameter and lack of sufficient preparation on the SQL query in the `has_checkout_consent()` method, allowing unauthenticated attackers to extract sensitive information from the database.
date: "2026-05-20T02:18:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - wordpress
  - plugin
  - cve-2026-3985
  - cloud
vendors:
  - WordPress
products:
  - Creative Mail – Easier WordPress & WooCommerce Email Marketing plugin <= 1.6.9
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-3985
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3985
rules:
  - title: Detect CVE-2026-3985 Exploitation Attempt via Creative Mail Plugin
    description: Detects CVE-2026-3985 exploitation attempt via Creative Mail plugin by looking for SQL injection patterns in the checkout_uuid parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-3985 Exploitation Attempt via Creative Mail Plugin - POST
    description: Detects CVE-2026-3985 exploitation attempt via Creative Mail plugin by looking for SQL injection patterns in the checkout_uuid parameter in POST requests.
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

The Creative Mail – Easier WordPress & WooCommerce Email Marketing plugin, a popular email marketing tool for WordPress, is vulnerable to SQL Injection. Specifically, versions up to and including 1.6.9 are susceptible. The vulnerability resides in the `has_checkout_consent()` method, stemming from insufficient escaping of the user-supplied `checkout_uuid` parameter, compounded by a lack of sufficient preparation on the existing SQL query. This flaw enables unauthenticated attackers to inject malicious SQL queries, potentially leading to the extraction of sensitive data from the WordPress database. Successful exploitation could compromise user credentials, customer data, and other confidential information stored within the database.

## Attack Chain

1.  An unauthenticated attacker identifies a WordPress site using the vulnerable Creative Mail plugin (version <= 1.6.9).
2.  The attacker crafts a malicious HTTP request targeting an endpoint that utilizes the `has_checkout_consent()` method.
3.  The malicious request includes a specifically crafted `checkout_uuid` parameter containing SQL injection payloads.
4.  The vulnerable `has_checkout_consent()` method fails to properly sanitize the `checkout_uuid` parameter.
5.  The unsanitized `checkout_uuid` parameter is incorporated into an SQL query without proper preparation or escaping.
6.  The injected SQL code is executed against the WordPress database.
7.  The attacker leverages the injected SQL to extract sensitive information, such as user credentials or customer data.
8.  The attacker may use the extracted data for malicious purposes, including account takeover or data theft.

## Impact

Successful exploitation of this SQL Injection vulnerability (CVE-2026-3985) can lead to the compromise of sensitive data stored in the WordPress database. This includes user credentials, customer information, and potentially other confidential data. The CVSS v3.1 base score for this vulnerability is 7.5, indicating a high level of severity. An attacker could gain unauthorized access to the WordPress site, potentially leading to further compromise and damage. The number of affected websites is unknown but could be significant, given the popularity of the Creative Mail plugin.

## Recommendation

*   Upgrade the Creative Mail – Easier WordPress & WooCommerce Email Marketing plugin to a version greater than 1.6.9 to patch CVE-2026-3985.
*   Deploy the Sigma rule "Detect CVE-2026-3985 Exploitation Attempt via Creative Mail Plugin" to your SIEM to identify potential exploitation attempts.
*   Monitor web server logs for suspicious requests containing SQL injection payloads in the `checkout_uuid` parameter (see example in Sigma rule test cases).
