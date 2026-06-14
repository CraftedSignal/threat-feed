---
title: WooCommerce Infinite Scroll Plugin Vulnerable to PHP Object Injection (CVE-2025-11993)
slug: 2026-05-woocommerce-php-object-injection
description: The WooCommerce Infinite Scroll and Ajax Pagination plugin for WordPress is vulnerable to PHP Object Injection (CVE-2025-11993) due to deserialization of untrusted data in the 'import_settings' function, potentially leading to arbitrary code execution if a suitable POP chain is present.
date: "2026-05-29T07:18:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - php-object-injection
  - wordpress
  - woocommerce
  - cve-2025-11993
vendors:
  - WooCommerce
products:
  - WooCommerce Infinite Scroll and Ajax Pagination <= 1.8
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2025-11993
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-11993
  - CVE-2025-11993
rules:
  - title: Detect WooCommerce Infinite Scroll PHP Object Injection Attempt
    description: Detects CVE-2025-11993 exploitation - attempts to inject PHP objects via the 'import_settings' function in the WooCommerce Infinite Scroll and Ajax Pagination plugin.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Potential PHP Object Injection via Serialized Data in HTTP Request
    description: Detects potential PHP Object Injection attempts by identifying serialized PHP objects within HTTP request bodies. This rule is generic and may require tuning to reduce false positives, but will catch a wider range of similar attacks.
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

The WooCommerce Infinite Scroll and Ajax Pagination plugin, versions 1.8 and earlier, contains a PHP Object Injection vulnerability (CVE-2025-11993). The vulnerability exists within the 'import_settings' function, which fails to properly validate data supplied via the 'settings' parameter during the import configuration process. This allows authenticated attackers with Subscriber-level access or higher to inject PHP objects by exploiting the deserialization of untrusted data. While the vulnerable plugin itself lacks a Property-Oriented Programming (POP) chain, the presence of such a chain in another plugin or theme installed on the target WordPress system could allow for arbitrary file deletion, sensitive data retrieval, or even code execution. This vulnerability poses a significant risk to WordPress sites utilizing the affected plugin and underscores the importance of careful input validation and regular security audits.

## Attack Chain

1. An attacker authenticates to a WordPress site with at least Subscriber-level privileges.
2. The attacker crafts a malicious payload containing a serialized PHP object designed to exploit a POP chain present in another installed plugin or theme.
3. The attacker accesses the import configuration functionality of the "WooCommerce Infinite Scroll and Ajax Pagination" plugin.
4. The attacker injects the malicious serialized PHP object into the 'settings' parameter of the 'import_settings' function.
5. The application deserializes the malicious PHP object without proper sanitization or validation.
6. If a suitable POP chain exists within the WordPress installation, the deserialized object triggers a sequence of method calls.
7. The POP chain is exploited to perform unauthorized actions such as deleting arbitrary files, retrieving sensitive information from the database (wp-config.php), or executing arbitrary PHP code.
8. The attacker achieves remote code execution on the target server, potentially compromising the entire WordPress site.

## Impact

Successful exploitation of this vulnerability (CVE-2025-11993) could allow an attacker to gain complete control of a vulnerable WordPress website. Depending on the available POP chains, attackers could delete critical files, steal sensitive information, or inject malicious code to further compromise the server and its hosted data. The number of affected sites is potentially large, given the widespread usage of WordPress and the WooCommerce plugin.

## Recommendation

*   Upgrade the "WooCommerce Infinite Scroll and Ajax Pagination" plugin to a patched version beyond 1.8 to remediate CVE-2025-11993.
*   Deploy the Sigma rule "Detect WooCommerce Infinite Scroll PHP Object Injection Attempt" to identify exploitation attempts targeting the 'import_settings' function.
*   Regularly audit installed WordPress plugins and themes for potential POP chains to reduce the risk of successful exploitation.
*   Implement strict input validation and sanitization measures to prevent deserialization of untrusted data.
