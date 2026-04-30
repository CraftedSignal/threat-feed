---
title: WC Lovers WCFM Marketplace SQL Injection Vulnerability (CVE-2025-63029)
slug: 2026-04-wcfm-sql-injection
description: An SQL Injection vulnerability, identified as CVE-2025-63029, exists in the WC Lovers WCFM Marketplace WordPress plugin up to version 3.7.1, potentially allowing attackers to execute arbitrary SQL queries.
date: "2026-04-15T17:17:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - wordpress
  - wcfm-marketplace
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-63029
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-63029
  - https://patchstack.com/database/wordpress/plugin/wc-multivendor-marketplace/vulnerability/wordpress-wcfm-marketplace-plugin-3-7-1-sql-injection-vulnerability?_s_id=cve
iocs:
  - type: url
    value: https://patchstack.com/database/wordpress/plugin/wc-multivendor-marketplace/vulnerability/wordpress-wcfm-marketplace-plugin-3-7-1-sql-injection-vulnerability?_s_id=cve
ioc_counts:
  url: 1
rules:
  - title: Detect Suspicious WCFM Marketplace SQL Injection Attempts
    description: Detects potential SQL injection attempts targeting the WC Lovers WCFM Marketplace plugin based on common SQL injection keywords in the URI query.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WCFM Marketplace SQL Injection via POST Data
    description: Detects potential SQL injection attempts targeting the WC Lovers WCFM Marketplace plugin by looking for SQL keywords in POST requests.
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

CVE-2025-63029 describes an SQL Injection vulnerability affecting the WC Lovers WCFM (WooCommerce Frontend Manager) Marketplace WordPress plugin. This vulnerability, present in versions up to and including 3.7.1, stems from improper neutralization of special elements within SQL commands. An attacker exploiting this flaw can inject malicious SQL code, potentially leading to unauthorized data access, modification, or deletion within the WordPress database. Given the widespread use of WordPress and the WCFM Marketplace plugin, this vulnerability poses a significant risk to e-commerce websites and their associated sensitive information. Successful exploitation could result in compromised customer data, financial losses, and reputational damage.

## Attack Chain

1. The attacker identifies a vulnerable WCFM Marketplace instance running a version <= 3.7.1.
2. The attacker crafts a malicious HTTP request containing SQL injection payloads in a vulnerable parameter.
3. The WCFM Marketplace plugin fails to properly sanitize the attacker-controlled input.
4. The unsanitized input is incorporated into an SQL query executed against the WordPress database.
5. The injected SQL code modifies the intended query logic.
6. The database server executes the attacker's malicious SQL query.
7. The attacker gains unauthorized access to sensitive data stored in the database, such as user credentials, financial information, or product details.
8. The attacker may modify or delete data, escalate privileges, or potentially gain control of the WordPress site.

## Impact

Successful exploitation of CVE-2025-63029 can have severe consequences. An attacker could gain complete control over the affected WordPress site's database. This can lead to the theft of sensitive customer data (e.g., usernames, passwords, addresses, payment information), modification of product listings and pricing, or even complete site defacement or takeover. The number of potentially affected sites is substantial, considering the popularity of the WCFM Marketplace plugin.

## Recommendation

*   Upgrade the WC Lovers WCFM Marketplace plugin to the latest available version, which includes a patch for CVE-2025-63029.
*   Deploy the Sigma rule "Detect Suspicious WCFM Marketplace SQL Injection Attempts" to your SIEM to identify potential exploitation attempts targeting this vulnerability.
*   Monitor web server logs for suspicious HTTP requests containing potential SQL injection payloads targeting the WCFM Marketplace plugin.
*   Review and harden database access controls to minimize the impact of potential SQL injection attacks.
