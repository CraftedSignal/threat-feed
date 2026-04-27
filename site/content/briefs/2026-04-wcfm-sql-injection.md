---
title: WC Lovers WCFM Marketplace SQL Injection Vulnerability (CVE-2025-63029)
slug: 2026-04-wcfm-sql-injection
description: An SQL Injection vulnerability, identified as CVE-2025-63029, exists in the WC Lovers WCFM Marketplace WordPress plugin up to version 3.7.1, potentially allowing attackers to execute arbitrary SQL queries.
date: "2026-04-15T17:17:00Z"
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

CVE-2025-63029 describes an SQL Injection vulnerability affecting the WC Lovers WCFM (WooCommerce Frontend Manager) Marketplace WordPress plugin. This vulnerability, present in versions up to and including 3.7.1, stems from improper neutralization of special elements within SQL commands. An attacker exploiting this flaw can inject malicious SQL code, potentially leading to unauthorized data access, modification, or deletion within the WordPress database. Given the widespread use of WordPress…
