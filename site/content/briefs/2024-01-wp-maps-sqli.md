---
title: WP Maps WordPress Plugin Time-Based SQL Injection Vulnerability (CVE-2026-2580)
slug: 2024-01-wp-maps-sqli
description: The WP Maps WordPress plugin before version 4.9.2 is vulnerable to time-based SQL Injection via the 'orderby' parameter, allowing unauthenticated attackers to extract sensitive information from the database.
date: "2026-03-23T00:16:51Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - wordpress
  - sqli
  - cve-2026-2580
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-2580
rules:
  - title: WP Maps Orderby SQL Injection Attempt
    description: Detects potential SQL injection attempts in the 'orderby' parameter of the WP Maps plugin.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: WP Maps Orderby SQL Injection Attempt - Error Based
    description: Detects potential SQL injection attempts in the 'orderby' parameter of the WP Maps plugin using error based techniques.
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

The WP Maps – Store Locator, Google Maps, OpenStreetMap, Mapbox, Listing, Directory & Filters plugin for WordPress, a widely used plugin for integrating map functionality into WordPress sites, contains a critical time-based SQL Injection vulnerability. Assigned CVE-2026-2580, this flaw affects all versions up to and including 4.9.1. The vulnerability lies within the 'orderby' parameter, where insufficient input sanitization allows unauthenticated attackers to inject malicious SQL queries. By…
