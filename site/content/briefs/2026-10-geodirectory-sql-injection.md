---
title: SQL Injection in GeoDirectory WordPress Plugin
slug: 2026-10-geodirectory-sql-injection
description: The GeoDirectory WordPress plugin (<= 2.8.186) is vulnerable to SQL injection, allowing authenticated attackers to execute arbitrary database queries via improper coordinate sanitization in the geodir_gps_query_part function.
date: "2026-10-03T06:54:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:geodirectory:geodirectory:*:*:*:*:*:wordpress:*:*
tags:
  - web-application-vulnerability
  - sql-injection
  - wordpress
vendors:
  - WordPress
products:
  - GeoDirectory (<= 2.8.186)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for authenticated attackers... to append additional SQL queries into already existing queries.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: that is later executed by the public wp_ajax_nopriv_geodir_widget_listings handler
    confidence_band: high
cves:
  - id: CVE-2026-103913
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103913
rules:
  - title: Detect CVE-2026-103913 Exploitation - SQL Injection in GeoDirectory
    description: Detects potential SQL injection attempts against the GeoDirectory plugin by monitoring for suspicious patterns in AJAX requests to the widget listings endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy WAF rules to sanitize requests containing SQL keywords directed at the GeoDirectory AJAX endpoint.
      owner: SOC
      due: 24h
      evidence: Plugin is vulnerable to SQL Injection.
  mitigation_plan:
    - priority: immediate
      action: Update GeoDirectory plugin to version > 2.8.186.
      owner: IT Operations
      addresses: CVE-2026-103913
      evidence: Plugin versions <= 2.8.186 are vulnerable.
---

The GeoDirectory plugin for WordPress, in versions up to and including 2.8.186, contains a SQL injection vulnerability. The flaw originates from the geodir_gps_query_part() function, which fails to properly escape or validate latitude and longitude coordinate values before interpolating them into a database query string. This vulnerability is triggered when the application handles requests through the wp_ajax_nopriv_geodir_widget_listings handler. An attacker with Subscriber-level access can supply a malicious, crafted latitude or longitude coordinate during a listing update process. When the application subsequently processes a request with the sort_by=distance_asc parameter, the unvalidated coordinate input is executed as part of a SQL query. This allows attackers to manipulate database queries, potentially leading to unauthorized data exfiltration or sensitive information disclosure from the underlying WordPress database.

## Impact

Successful exploitation of this vulnerability allows authenticated attackers with minimal privileges (Subscriber) to read sensitive data from the site database. This could include user credentials, personally identifiable information (PII), or other sensitive configuration data stored in the WordPress environment. The impact is significant for organizations relying on GeoDirectory for their business listings or directory services.

## Recommendation

Update the GeoDirectory plugin to a patched version beyond 2.8.186 immediately. Ensure that all WordPress plugins are kept up to date and that administrative/subscriber privileges are strictly managed. Conduct a audit of database logs for unusual query patterns originating from the wp_ajax_nopriv_geodir_widget_listings handler.
