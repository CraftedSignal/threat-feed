---
title: WooCommerce Ajax Product Filter Plugin Vulnerable to SQL Injection (CVE-2026-3396)
slug: 2026-04-woocommerce-sqli
description: The WCAPF - WooCommerce Ajax Product Filter plugin is vulnerable to time-based SQL Injection (CVE-2026-3396) due to insufficient escaping and SQL query preparation, allowing unauthenticated attackers to extract sensitive information from the database in versions up to 4.2.3.
date: "2026-04-08T12:16:21Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - woocommerce
  - sqli
  - cve-2026-3396
  - wordpress
  - plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-3396
    cvss: 7.5
    epss: 0.16994
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3396
rules:
  - title: Detect WooCommerce SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the WooCommerce Ajax Product Filter plugin by looking for common SQL injection keywords in the URI query.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WooCommerce Slow SQL Injection via SLEEP
    description: Detects potential time-based SQL injection attempts targeting the WooCommerce Ajax Product Filter plugin by looking for the SLEEP() function in the URI query.
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

The WooCommerce Ajax Product Filter (WCAPF) plugin, a WordPress extension, is susceptible to a time-based SQL Injection vulnerability (CVE-2026-3396). This flaw stems from inadequate input sanitization of the `post-author` parameter and insufficient preparation within the existing SQL query structure. Specifically, all versions of the plugin up to and including version 4.2.3 are affected. An unauthenticated attacker can exploit this vulnerability by injecting malicious SQL code into the `post-author` parameter. Successful exploitation allows the attacker to manipulate database queries and extract sensitive information without requiring authentication. This vulnerability poses a significant risk to e-commerce sites using the WCAPF plugin, as attackers could potentially access customer data, administrative credentials, or other confidential information.

## Attack Chain

1.  An unauthenticated attacker identifies a WooCommerce website using a vulnerable version (<=4.2.3) of the WCAPF plugin.
2.  The attacker crafts a malicious HTTP request targeting an endpoint that utilizes the vulnerable `post-author` parameter.
3.  The crafted request includes SQL injection payload within the `post-author` parameter, designed to extract data using time-based techniques. For example, the attacker might use a `SLEEP()` function to introduce delays based on conditional database queries.
4.  The web server processes the request and passes the unsanitized `post-author` parameter to the database query.
5.  The injected SQL code manipulates the original query, causing the database to execute the attacker's malicious commands.
6.  Based on the response time (due to the `SLEEP()` function), the attacker infers whether their injected SQL query was successful in retrieving specific data.
7.  The attacker iteratively refines their SQL injection payload to extract sensitive information, such as user credentials or customer details.
8.  The attacker exfiltrates the obtained data, potentially using it for identity theft, financial fraud, or further attacks against the compromised website.

## Impact

Successful exploitation of CVE-2026-3396 can lead to the complete compromise of the vulnerable WooCommerce website's database. An attacker could potentially access sensitive customer data, including names, addresses, credit card details, and purchase history. Furthermore, administrative credentials could be stolen, allowing the attacker to gain full control over the website. This can result in significant financial losses, reputational damage, and legal liabilities for the affected e-commerce business. While the exact number of affected websites is unknown, any online store using the WCAPF plugin versions 4.2.3 or earlier is potentially at risk.

## Recommendation

*   Upgrade the WCAPF plugin to a version greater than 4.2.3 to patch CVE-2026-3396 (references: CVE-2026-3396).
*   Deploy the Sigma rule `Detect WooCommerce SQL Injection Attempt` to identify potential exploitation attempts in web server logs (references: Sigma rule).
*   Implement input validation and sanitization on the `post-author` parameter to prevent SQL injection attacks (references: Attack Chain).
*   Monitor web server logs for suspicious requests containing SQL injection payloads, particularly those targeting WCAPF plugin endpoints (references: Sigma rule, Attack Chain).
