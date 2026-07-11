---
title: WordPress Booking Package Plugin Vulnerable to Unauthenticated SQL Injection
slug: 2026-07-booking-package-sqli
description: The Booking Package plugin for WordPress is vulnerable to unauthenticated generic SQL Injection via the 'email' form parameter in versions up to and including 1.7.20, allowing attackers to extract sensitive information from the database.
date: "2026-07-11T05:18:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - sqli
  - web-vulnerability
  - cms
vendors:
  - WordPress
products:
  - Booking Package plugin <= 1.7.20
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1505
    technique_name: Server Software Component
    evidence: This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.
    confidence_band: high
cves:
  - id: CVE-2026-15335
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15335
---

The Booking Package plugin for WordPress, in all versions up to and including 1.7.20, is susceptible to an unauthenticated generic SQL Injection vulnerability, identified as CVE-2026-15335. This vulnerability resides in the `/wp-json/booking-package/v1/request` REST API endpoint, where the 'email' form parameter is processed with insufficient input sanitization and without the use of prepared statements. Consequently, attackers can inject arbitrary SQL queries into existing database queries, potentially leading to the extraction of sensitive information from the WordPress database. The endpoint's `permission_callback: __return_true` configuration and the lack of `wp_magic_quotes` for REST-sourced `$_POST` values mean that single quotes in an attacker's payload can reach the SQL sink intact, bypassing authentication. While the 'email' parameter is subject to `is_email` validation, an attacker could craft payloads that initially conform to an email format before breaking out to append malicious SQL queries.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress installation running the Booking Package plugin version 1.7.20 or earlier.
2. The attacker crafts an HTTP POST request targeting the vulnerable REST API endpoint: `/wp-json/booking-package/v1/request`.
3. A malicious SQL injection payload is embedded within the 'email' form parameter in the body of the POST request, designed to bypass `is_email` validation and append further SQL queries (e.g., `test@example.com' UNION SELECT ... --`).
4. The request is processed by the plugin, bypassing authentication due to the endpoint's permissive `permission_callback` setting.
5. The lack of proper input escaping and prepared statements allows the injected SQL payload, including single quotes, to be interpreted as part of the database query.
6. The appended malicious SQL queries execute on the underlying database, enabling the attacker to extract sensitive data.
7. The sensitive information, such as user credentials, PII, or other critical database contents, is returned to the attacker within the HTTP response.

## Impact

Successful exploitation of CVE-2026-15335 allows unauthenticated attackers to gain unauthorized access to sensitive information stored in the WordPress database. This could include user accounts, personal data, application configurations, or other critical business data. Although the 'email' parameter undergoes `is_email` validation, determined attackers can craft payloads to circumvent this, leading to data breaches. The broad usage of WordPress and the Booking Package plugin means a significant number of websites could be at risk if not updated promptly.

## Recommendation

* Patch CVE-2026-15335 immediately by updating the Booking Package plugin for WordPress to a version greater than 1.7.20.
* Implement a Web Application Firewall (WAF) to detect and block common SQL injection patterns, especially those targeting the `/wp-json/booking-package/v1/request` endpoint.
