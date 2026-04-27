---
title: Riaxe Product Customizer WordPress Plugin SQL Injection Vulnerability
slug: 2024-01-wordpress-sqli
description: The Riaxe Product Customizer plugin for WordPress is vulnerable to SQL Injection via the 'options' parameter within 'product_data' of the `/wp-json/InkXEProductDesignerLite/add-item-to-cart` REST API endpoint, allowing unauthenticated attackers to extract sensitive information from the database.
date: "2026-04-16T06:16:17Z"
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

The Riaxe Product Customizer plugin, a WordPress plugin, is susceptible to SQL Injection attacks. This vulnerability resides within the `/wp-json/InkXEProductDesignerLite/add-item-to-cart` REST API endpoint, specifically through the 'options' parameter keys nested within the 'product_data'. All versions of the plugin up to and including 2.1.2 are affected. Due to insufficient input sanitization and inadequate preparation of SQL queries, unauthenticated attackers can inject malicious SQL code…
