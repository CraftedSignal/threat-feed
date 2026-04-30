---
title: Riaxe Product Customizer WordPress Plugin SQL Injection Vulnerability
slug: 2024-01-wordpress-sqli
description: The Riaxe Product Customizer plugin for WordPress is vulnerable to SQL Injection via the 'options' parameter within 'product_data' of the `/wp-json/InkXEProductDesignerLite/add-item-to-cart` REST API endpoint, allowing unauthenticated attackers to extract sensitive information from the database.
date: "2026-04-16T06:16:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - sqli
  - plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-3599
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3599
rules:
  - title: Detect SQL Injection Attempts via Riaxe Product Customizer Plugin
    description: Detects potential SQL injection attempts targeting the Riaxe Product Customizer plugin in WordPress based on the request URI and POST data.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Attempts via Riaxe Product Customizer Plugin - Error Based
    description: Detects potential error-based SQL injection attempts targeting the Riaxe Product Customizer plugin in WordPress based on the request URI and POST data using common error-inducing SQL fragments.
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

The Riaxe Product Customizer plugin, a WordPress plugin, is susceptible to SQL Injection attacks. This vulnerability resides within the `/wp-json/InkXEProductDesignerLite/add-item-to-cart` REST API endpoint, specifically through the 'options' parameter keys nested within the 'product_data'. All versions of the plugin up to and including 2.1.2 are affected. Due to insufficient input sanitization and inadequate preparation of SQL queries, unauthenticated attackers can inject malicious SQL code. Successful exploitation enables attackers to execute arbitrary SQL queries, potentially leading to sensitive data extraction. This poses a significant risk to WordPress sites utilizing the affected plugin, as attackers could gain access to user credentials, financial information, or other confidential data stored in the database. Defenders should prioritize patching or removing the plugin to mitigate this threat.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site using a vulnerable version (<=2.1.2) of the Riaxe Product Customizer plugin.
2. The attacker crafts a malicious HTTP POST request targeting the `/wp-json/InkXEProductDesignerLite/add-item-to-cart` REST API endpoint.
3. The crafted request includes a 'product_data' parameter containing a manipulated 'options' array.
4. Within the 'options' array, the attacker injects SQL code into one or more of the parameter keys.
5. The WordPress server processes the request without properly sanitizing the injected SQL code.
6. The application constructs a SQL query using the unsanitized input, effectively injecting the malicious code into the query.
7. The database server executes the attacker-controlled SQL query.
8. The attacker extracts sensitive information from the database, such as user credentials, by using the SQL injection vulnerability.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-3599) allows unauthenticated attackers to extract sensitive information from the WordPress database. This may include user credentials (usernames, email addresses, and password hashes), customer data, financial information, and other confidential data stored within the database. The impact can range from defacement of the website and data theft, to complete compromise of the WordPress site and its associated server. Due to the widespread use of WordPress and its plugins, this vulnerability poses a significant threat to a potentially large number of websites.

## Recommendation

*   Upgrade the Riaxe Product Customizer plugin to a version higher than 2.1.2 to patch CVE-2026-3599.
*   Deploy the Sigma rule `Detect SQL Injection Attempts via Riaxe Product Customizer Plugin` to your SIEM to detect exploitation attempts.
*   Monitor web server logs for suspicious POST requests to the `/wp-json/InkXEProductDesignerLite/add-item-to-cart` endpoint.
