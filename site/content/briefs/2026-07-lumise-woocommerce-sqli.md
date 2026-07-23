---
title: 'CVE-2026-9713: Lumise Product Designer for WooCommerce Plugin SQL Injection'
slug: 2026-07-lumise-woocommerce-sqli
description: The Lumise Product Designer for WooCommerce plugin for WordPress, in versions up to and including 2.1.1, is vulnerable to SQL Injection via the 'id' and 'table' parameters within an uploaded cart JSON file processed by the checkout AJAX action, allowing unauthenticated attackers to extract sensitive database information.
date: "2026-07-23T08:18:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - woocommerce
  - sql-injection
  - web-vulnerability
  - cve
vendors:
  - Lumise
  - WordPress
products:
  - Lumise Product Designer for WooCommerce (<= 2.1.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Lumise Product Designer for WooCommerce plugin for WordPress is vulnerable to SQL Injection via the 'id' and 'table' parameters in the uploaded cart JSON file processed by the checkout AJAX action.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1505
    technique_name: Server Software Component
    evidence: This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.
    confidence_band: high
cves:
  - id: CVE-2026-9713
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9713
rules:
  - title: Detects CVE-2026-9713 Exploitation - Lumise WooCommerce SQLi Attempt
    description: Detects CVE-2026-9713 exploitation - Unauthenticated SQL Injection attempt in Lumise Product Designer for WooCommerce via suspicious SQL metacharacters in POST body to admin-ajax.php with action=lumise_checkout.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1505
    data_sources:
      - webserver
rules_count: 1
---

A critical SQL Injection vulnerability, tracked as CVE-2026-9713, affects the Lumise Product Designer for WooCommerce plugin for WordPress, impacting all versions up to and including 2.1.1. This flaw allows unauthenticated attackers to exploit the 'id' and 'table' parameters found within an uploaded cart JSON file. These parameters are handled by the plugin's checkout AJAX action, specifically within the `find_resource()` function, where they are insufficiently escaped before being directly appended to a raw SQL query. Neither `wp_magic_quotes` nor `$wpdb->prepare()` adequately protect these inputs. Attackers can leverage this vulnerability to inject additional SQL queries, enabling them to extract sensitive information from the underlying WordPress database, posing a significant risk to data confidentiality.

## Attack Chain

1. An unauthenticated attacker crafts a malicious JSON file containing specially formatted `id` and `table` parameters with SQL injection payloads.
2. The attacker sends an HTTP POST request to the `/wp-admin/admin-ajax.php` endpoint on the vulnerable WordPress site, specifying the `action=lumise_checkout` parameter.
3. The crafted JSON file is included in the request body as part of the "uploaded cart" data.
4. The `lumise_checkout` AJAX action processes the request and calls the `find_resource()` function.
5. Inside `find_resource()`, the malicious `id` and `table` parameters from the JSON file are directly interpolated into a raw SQL query without proper escaping or sanitization.
6. The injected SQL commands execute against the WordPress database, allowing the attacker to bypass authentication and retrieve sensitive information.
7. The attacker receives database query results, potentially containing user credentials, customer data, or other proprietary information, within the server's response.

## Impact

Successful exploitation of CVE-2026-9713 allows unauthenticated attackers to extract sensitive data directly from the WordPress database. This can include user details, hashed passwords, order information, and other proprietary business data stored by the WooCommerce plugin. The compromise of such information can lead to severe privacy breaches, financial fraud, reputational damage, and further exploitation of the affected website and its users. Given the unauthenticated nature of the vulnerability, any internet-facing WordPress site using the affected plugin is at risk.

## Recommendation

* Patch CVE-2026-9713 on all affected WordPress installations running the Lumise Product Designer for WooCommerce plugin immediately by updating to a version greater than 2.1.1.
* Deploy the Sigma rule below to your SIEM to detect attempts at exploiting CVE-2026-9713.
* Review web server logs for HTTP POST requests to `/wp-admin/admin-ajax.php` containing `action=lumise_checkout` and suspicious SQL-like strings in the request body.
