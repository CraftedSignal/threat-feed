---
title: WordPress Premium Packages Plugin SQL Injection Vulnerability (CVE-2026-12800)
slug: 2026-07-premium-packages-wordpress-sqli
description: The Premium Packages - Sell Digital Products Securely plugin for WordPress, in versions up to and including 6.2.0, is vulnerable to SQL Injection via the 'code' parameter of the POST /wp-json/wpdmpp/v1/cart/coupon REST API endpoint, allowing unauthenticated attackers to append additional SQL queries to extract sensitive database information.
date: "2026-07-28T09:18:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - sql-injection
  - web-application
  - unauthenticated
vendors:
  - WPDMPP
products:
  - Premium Packages – Sell Digital Products Securely (< 6.2.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Premium Packages – Sell Digital Products Securely plugin for WordPress is vulnerable to SQL Injection via the 'code' parameter of the POST /wp-json/wpdmpp/v1/cart/coupon REST API endpoint...This makes it possible for unauthenticated attackers to append additional SQL queries...
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1505
    technique_name: Server Software Component
    evidence: This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.
    confidence_band: med
cves:
  - id: CVE-2026-12800
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12800
rules:
  - title: Detect CVE-2026-12800 Exploitation - WordPress Premium Packages Plugin SQLi
    description: Detects CVE-2026-12800 exploitation - Unauthenticated SQL Injection attempts against the WordPress Premium Packages plugin via the 'code' parameter in the /wp-json/wpdmpp/v1/cart/coupon REST API endpoint.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1505.001
    data_sources:
      - webserver
rules_count: 1
---

A critical SQL Injection vulnerability, tracked as CVE-2026-12800, has been identified in the Premium Packages - Sell Digital Products Securely plugin for WordPress, affecting all versions up to and including 6.2.0. This flaw resides within the `CouponCodes::find()` method, specifically impacting the 'code' parameter of the POST /wp-json/wpdmpp/v1/cart/coupon REST API endpoint. The vulnerability stems from insufficient input escaping, where user-supplied data is directly interpolated into a raw SQL query string without proper sanitization, such as using `$wpdb->prepare()` or `esc_sql()`. This design weakness enables unauthenticated attackers to inject arbitrary SQL queries, thereby extending existing database operations. Successful exploitation can lead to unauthorized access and exfiltration of sensitive information stored within the WordPress database, posing a significant risk to data confidentiality and integrity.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site running the Premium Packages - Sell Digital Products Securely plugin version 6.2.0 or earlier.
2. The attacker crafts a malicious HTTP POST request targeting the `/wp-json/wpdmpp/v1/cart/coupon` REST API endpoint.
3. The request includes a specially crafted 'code' parameter containing SQL injection payloads (e.g., `' OR 1=1 --`).
4. The vulnerable plugin processes the 'code' parameter without proper escaping or sanitization.
5. The malicious input is directly concatenated into a raw SQL query within the `CouponCodes::find()` method.
6. The database executes the modified SQL query, allowing the attacker to bypass authentication, retrieve arbitrary data, or potentially manipulate database content.
7. The attacker extracts sensitive information such as user credentials, order details, or other proprietary data from the database.

## Impact

Successful exploitation of CVE-2026-12800 allows unauthenticated attackers to perform arbitrary SQL queries against the WordPress database. This can lead to the full compromise of sensitive data, including but not limited to user accounts, session tokens, personal identifiable information (PII), and payment-related details if stored in the database. The exfiltration of such data can result in significant financial losses, reputational damage, regulatory penalties, and further attacks leveraging compromised credentials. The broad installation base of WordPress plugins implies a wide potential victim scope for organizations utilizing this plugin.

## Recommendation

* Patch CVE-2026-12800 immediately by updating the Premium Packages - Sell Digital Products Securely plugin to version 6.2.1 or newer.
* Deploy the `Detect CVE-2026-12800 Exploitation - WordPress Premium Packages Plugin SQLi` Sigma rule to your SIEM for early detection of exploitation attempts.
* Enable comprehensive web server logging for the `webserver` category, including full request URI and query parameters, to ensure the detection rule can be fully utilized.
