---
title: WooCommerce Ajax Product Filter Plugin Vulnerable to SQL Injection (CVE-2026-3396)
slug: 2026-04-woocommerce-sqli
description: The WCAPF - WooCommerce Ajax Product Filter plugin is vulnerable to time-based SQL Injection (CVE-2026-3396) due to insufficient escaping and SQL query preparation, allowing unauthenticated attackers to extract sensitive information from the database in versions up to 4.2.3.
date: "2026-04-08T12:16:21Z"
severities:
  - high
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

The WooCommerce Ajax Product Filter (WCAPF) plugin, a WordPress extension, is susceptible to a time-based SQL Injection vulnerability (CVE-2026-3396). This flaw stems from inadequate input sanitization of the `post-author` parameter and insufficient preparation within the existing SQL query structure. Specifically, all versions of the plugin up to and including version 4.2.3 are affected. An unauthenticated attacker can exploit this vulnerability by injecting malicious SQL code into the…
