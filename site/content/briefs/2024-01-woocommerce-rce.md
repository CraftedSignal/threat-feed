---
title: Woocommerce Custom Product Addons Pro Plugin RCE Vulnerability (CVE-2026-4001)
slug: 2024-01-woocommerce-rce
description: The Woocommerce Custom Product Addons Pro plugin for WordPress is vulnerable to Remote Code Execution (RCE) due to insufficient sanitization of user-submitted field values, allowing unauthenticated attackers to execute arbitrary code via crafted WCPA text fields.
date: "2024-01-29T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - woocommerce
  - rce
  - code-injection
  - cve-2026-4001
vendors:
  - Woocommerce
products:
  - Custom Product Addons Pro plugin
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4001
rules:
  - title: Detect WooCommerce Custom Product Addons RCE Attempt via URI Query
    description: Detects potential remote code execution attempts against the Woocommerce Custom Product Addons Pro plugin by monitoring HTTP requests containing suspicious patterns in the URI query.
    platform: sigma
    severity: critical
    tactics:
      - cve-2026-4001
      - execution
      - rce
    techniques:
      - T1505
    data_sources:
      - webserver
      - linux
  - title: Detect Woocommerce Custom Product Addons RCE Attempt via HTTP POST data
    description: Detects potential remote code execution attempts against the Woocommerce Custom Product Addons Pro plugin by monitoring HTTP requests containing suspicious PHP code in the POST data.
    platform: sigma
    severity: critical
    tactics:
      - cve-2026-4001
      - execution
      - rce
    techniques:
      - T1505
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Woocommerce Custom Product Addons Pro plugin for WordPress is vulnerable to Remote Code Execution (RCE) in versions up to and including 5.4.1. This vulnerability, identified as CVE-2026-4001, stems from a flaw in the `process_custom_formula()` function within `includes/process/price.php`. The plugin fails to adequately sanitize and validate user-submitted field values before passing them to PHP's `eval()` function, specifically when a custom pricing formula is used. The `sanitize_values()` method only strips HTML tags and does not escape single quotes or prevent PHP code injection. This vulnerability enables unauthenticated attackers to inject and execute arbitrary PHP code on the server. Successful exploitation can lead to complete server compromise, data exfiltration, and denial of service. Defenders should be aware of potential exploitation attempts targeting this vulnerability to prevent unauthorized access and maintain system integrity.

## Attack Chain

1.  An unauthenticated attacker identifies a WordPress site using a vulnerable version (<=5.4.1) of the Woocommerce Custom Product Addons Pro plugin.
2.  The attacker locates a product page with a WCPA text field configured with a custom pricing formula (pricingType: "custom" with {this.value}).
3.  The attacker crafts a malicious payload containing PHP code designed for remote code execution. This payload is injected into the WCPA text field.
4.  The attacker submits the form with the crafted payload.
5.  The `process_custom_formula()` function in `includes/process/price.php` receives the unsanitized input.
6.  The `sanitize_values()` method strips HTML tags but fails to prevent PHP code injection due to insufficient escaping of single quotes and other special characters.
7.  The malicious payload is then passed to the `eval()` function, which executes the injected PHP code.
8.  The attacker achieves Remote Code Execution (RCE) on the server, potentially gaining the ability to execute system commands, install malware, or steal sensitive data.

## Impact

Successful exploitation of CVE-2026-4001 allows unauthenticated attackers to execute arbitrary code on the targeted WordPress server. This can lead to complete server compromise, allowing attackers to gain full control over the website and its data. Potential impacts include defacement of the website, theft of sensitive customer data, installation of backdoors for persistent access, and use of the server for malicious activities such as spamming or hosting phishing sites. Given the popularity of Woocommerce, a large number of e-commerce sites are potentially vulnerable.

## Recommendation

*   Apply the latest security patches or upgrade to a version of the Woocommerce Custom Product Addons Pro plugin that addresses CVE-2026-4001, specifically versions greater than 5.4.1.
*   Inspect web server logs for suspicious POST requests to WordPress pages containing WCPA text fields with custom pricing formulas, using the provided Sigma rule targeting `cs-uri-query` in webserver logs.
*   Implement input validation and sanitization measures beyond HTML tag stripping to prevent code injection, particularly for fields passed to PHP's `eval()` function.
*   Monitor file system changes in the WordPress plugins directory (`/wp-content/plugins/`) for unauthorized modifications or new file creations using file integrity monitoring tools.
