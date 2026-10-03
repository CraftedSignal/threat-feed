---
title: Second-Order SQL Injection in WP Visitor Statistics Plugin
slug: 2026-10-wp-visitor-statistics-sqli
description: The WP Visitor Statistics plugin (up to 8.7) is vulnerable to a second-order SQL injection allowing unauthenticated attackers to exfiltrate database information via the 'fullRef' parameter.
date: "2026-10-03T08:54:49Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:wp_visitor_statistics:*:*:*:*:*:*:*:*
tags:
  - sqli
  - web-application
  - wordpress
vendors:
  - WordPress
products:
  - WP Visitor Statistics (Real Time Traffic) (<= 8.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can supply a malicious value to the 'fullRef' parameter via the wmcTrack endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-96267
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96267
rules:
  - title: Detect CVE-2026-96267 Exploitation - SQL Injection in wmcTrack Endpoint
    description: Detects potential SQL injection attempts against the WP Visitor Statistics plugin by monitoring the wmcTrack endpoint for common SQL metacharacters.
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
    - IT Operations
  immediate_actions:
    - action: Audit web logs for requests targeting 'wmcTrack' containing suspicious characters.
      owner: SOC
      due: 24h
      evidence: Source document identifies the tracking endpoint as the injection vector.
  mitigation_plan:
    - priority: immediate
      action: Disable or update the WP Visitor Statistics plugin to a patched version.
      owner: IT Operations
      addresses: CVE-2026-96267
      evidence: Plugin version <= 8.7 is vulnerable.
---

The WP Visitor Statistics (Real Time Traffic) plugin for WordPress, in all versions up to and including 8.7, contains a second-order SQL injection vulnerability. The flaw exists due to insufficient input validation and parameter escaping on the 'fullRef' parameter handled by the plugin's tracking endpoint. An unauthenticated attacker can submit a malicious referrer URL to the 'wmcTrack' endpoint, which the plugin stores in the 'wp_logVisit' database table without sanitization. The malicious payload is subsequently executed when an administrator logs in and accesses the 'Traffic Sources' dashboard. This vulnerability allows for potential unauthorized data extraction from the WordPress database. Defenders should monitor web server logs for suspicious requests to the tracking endpoint containing SQL syntax characters.

## Attack Chain

1. Attacker identifies a target running WP Visitor Statistics (Real Time Traffic) <= 8.7.
2. Attacker crafts a malicious HTTP GET or POST request targeting the 'wmcTrack' tracking endpoint.
3. Attacker injects a SQL payload into the 'fullRef' parameter value.
4. The plugin accepts the input and persists the unescaped malicious string into the 'wp_logVisit' table.
5. The attacker waits for an administrator with sufficient privileges to access the WordPress backend.
6. The administrator navigates to the 'Traffic Sources' dashboard.
7. The application retrieves the poisoned data from 'wp_logVisit' and executes the malicious SQL query.
8. The injected query executes, potentially exfiltrating sensitive data from the database.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to execute arbitrary SQL queries against the WordPress database when an administrator views the plugin's traffic dashboard. This may result in the exfiltration of sensitive configuration data, user credentials, or other stored content within the database.

## Recommendation

Update the WP Visitor Statistics (Real Time Traffic) plugin to the latest version once a patch is available. Until a patch is applied, disable the plugin to prevent unauthenticated data injection. Configure Web Application Firewalls (WAF) to inspect the 'fullRef' parameter for common SQL injection patterns.

## Detection

Detect malicious tracking requests by inspecting web access logs for characters typically associated with SQL injection (e.g., single quotes, semicolons, comments) within the query string or body targeted at the tracking endpoint.
