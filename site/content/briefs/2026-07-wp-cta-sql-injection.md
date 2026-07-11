---
title: WP CTA Plugin Vulnerable to Unauthenticated Time-Based Blind SQL Injection (CVE-2026-4661)
slug: 2026-07-wp-cta-sql-injection
description: The WP CTA - Sticky CTA Builder, Generate Leads, Promote Sales plugin for WordPress is vulnerable to time-based blind SQL Injection via the 'fildname' parameter in versions up to and including 2.2.2. This vulnerability is due to insufficient escaping of user-supplied column names and lack of preparation in database queries. Unauthenticated attackers can exploit this by injecting arbitrary SQL queries to extract sensitive information, including administrator password hashes, from the database.
date: "2026-07-11T07:22:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - sql-injection
  - time-based-blind
  - unauthenticated
  - web-vulnerability
vendors:
  - WordPress
products:
  - WP CTA – Sticky CTA Builder, Generate Leads, Promote Sales plugin <= 2.2.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The endpoint being registered for unauthenticated users via wp_ajax_nopriv_. This makes it possible for unauthenticated attackers to inject arbitrary SQL queries
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1505
    technique_name: Server Software Component
    evidence: vulnerable to time-based blind SQL Injection via the 'fildname' parameter ... unauthenticated attackers to inject arbitrary SQL queries and extract sensitive information from the database via time-based blind SQL injection techniques, including administrator password hashes.
    confidence_band: high
cves:
  - id: CVE-2026-4661
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4661
rules:
  - title: Detects CVE-2026-4661 Exploitation - WP CTA Plugin Time-Based Blind SQLi
    description: Detects exploitation attempts against CVE-2026-4661, an unauthenticated time-based blind SQL Injection vulnerability in the WP CTA WordPress plugin, by looking for SQLi payloads in the 'fildname' parameter of POST requests to admin-ajax.php.
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

The "WP CTA - Sticky CTA Builder, Generate Leads, Promote Sales" plugin for WordPress contains a critical vulnerability, CVE-2026-4661, affecting all versions up to and including 2.2.2. This flaw allows unauthenticated attackers to perform time-based blind SQL Injection due to insufficient sanitization of the `fildname` parameter within the `ajaxCheck()` method and a lack of proper prepared statements in the `$wpdb->update()` call. Compounding the issue, the vulnerable endpoint is accessible to unauthenticated users via `wp_ajax_nopriv_` and lacks any authorization checks. This means threat actors can remotely inject arbitrary SQL queries into the site's database, allowing them to extract sensitive information, including administrator password hashes, without requiring any prior authentication or user interaction. Exploitation of this vulnerability could lead to full site compromise and data exfiltration.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress instance running the vulnerable "WP CTA - Sticky CTA Builder, Generate Leads, Promote Sales" plugin.
2. The attacker sends an HTTP POST request to the `wp-admin/admin-ajax.php` endpoint, specifying `action=cta_ajax_check` to invoke the vulnerable function.
3. The attacker injects a time-based blind SQL injection payload into the `fildname` parameter within the POST request.
4. The server processes the malicious SQL query embedded in `fildname`, causing a noticeable delay in the HTTP response due to functions like `SLEEP()` or `BENCHMARK()`.
5. By observing these time delays, the attacker iteratively infers database schema information, including table names and column names.
6. The attacker crafts subsequent time-based payloads to progressively extract sensitive data, such as entries from the `wp_users` table.
7. Specifically, the attacker targets and extracts administrator password hashes, potentially enabling offline cracking or credential stuffing attacks.
8. Successful exploitation culminates in the exfiltration of sensitive database contents and potential full administrative control over the WordPress site.

## Impact

Successful exploitation of CVE-2026-4661 allows unauthenticated attackers to extract arbitrary sensitive data directly from the WordPress database. The most critical impact is the potential exfiltration of administrator password hashes, which can then be used to gain full control over the compromised website. This could lead to website defacement, injection of malicious content, complete data loss, or further exploitation of site visitors. Organizations using the vulnerable plugin face significant risks of data breaches, reputational damage, and operational disruption. The unauthenticated nature of the vulnerability means any exposed WordPress site running the plugin is a potential target.

## Recommendation

* Patch CVE-2026-4661 by updating the "WP CTA - Sticky CTA Builder, Generate Leads, Promote Sales" plugin to a version greater than 2.2.2 immediately.
* Deploy the Sigma rule in this brief to your SIEM and tune for your environment to detect exploitation attempts against CVE-2026-4661.
* Review web server logs for suspicious HTTP POST requests to `/wp-admin/admin-ajax.php` containing SQL injection payloads in the `fildname` parameter as described in the attack chain.
