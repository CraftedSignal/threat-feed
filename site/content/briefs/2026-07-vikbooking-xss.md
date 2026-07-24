---
title: VikBooking Hotel Booking Engine & PMS Plugin Vulnerable to Stored Cross-Site Scripting (CVE-2026-15401)
slug: 2026-07-vikbooking-xss
description: The VikBooking Hotel Booking Engine & PMS plugin for WordPress versions up to and including 1.8.13 is vulnerable to Stored Cross-Site Scripting (XSS) via the 'vbfX' parameter, allowing unauthenticated attackers to inject arbitrary web scripts that execute when a user accesses an infected page.
date: "2026-07-24T10:18:13Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - wordpress
  - xss
  - web-vulnerability
  - stored-xss
  - cms
vendors:
  - VikBooking
products:
  - VikBooking Hotel Booking Engine & PMS plugin for WordPress (<= 1.8.13)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2026-15401
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15401
rules:
  - title: Detects CVE-2026-15401 Exploitation - VikBooking XSS Payload Delivery
    description: Detects CVE-2026-15401 exploitation - unauthenticated HTTP POST request to /wp-admin/admin-ajax.php with an XSS payload in the 'vbfX' parameter for the 'saveorder' action, indicating an attempt to inject stored XSS.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.007
      - T1547.001
    data_sources:
      - webserver
rules_count: 1
---

A critical Stored Cross-Site Scripting (XSS) vulnerability, identified as CVE-2026-15401, has been discovered in the VikBooking Hotel Booking Engine & PMS plugin for WordPress, affecting all versions up to and including 1.8.13. This flaw stems from insufficient input sanitization and output escaping of the 'vbfX' parameter. Exploitation is possible by unauthenticated attackers who can inject arbitrary web scripts into pages. The vulnerability exists because the public-facing 'saveorder' task, responsible for storing the 'vbfX' custom-field value, lacks proper capability and authentication checks. This allows a malicious payload to be submitted without authentication and stored in the database. When a legitimate user subsequently accesses a page displaying the stored 'vbfX' value, the injected script executes in their browser, leading to potential data theft, session hijacking, or defacement. This poses a significant risk to websites using the vulnerable plugin.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress website running a vulnerable version of the VikBooking Hotel Booking Engine & PMS plugin (<= 1.8.13).
2. The attacker crafts a malicious JavaScript payload designed to perform actions like session hijacking, data exfiltration, or defacement.
3. The attacker sends an unauthenticated HTTP POST request to the WordPress site's `admin-ajax.php` endpoint.
4. In the request body, the attacker includes `action=saveorder` and embeds the crafted XSS payload within the `vbfX` parameter.
5. Due to insufficient input validation, the vulnerable plugin processes and stores the malicious `vbfX` content in the WordPress database without authentication.
6. A legitimate user (e.g., an administrator or a visitor viewing booking information) navigates to a page that renders the previously stored `vbfX` custom field.
7. The browser of the legitimate user executes the attacker's injected script, leading to compromise of the user's session, unauthorized actions, or other malicious outcomes.
8. The attacker gains control over the victim's browser session, allowing for cookie theft, arbitrary actions on behalf of the victim, or content defacement.

## Impact

Successful exploitation of CVE-2026-15401 allows unauthenticated attackers to inject persistent malicious web scripts into affected WordPress sites. When executed in a victim's browser, these scripts can lead to significant consequences, including the theft of sensitive user data (such as session cookies, allowing for session hijacking), website defacement, redirection to malicious sites, or the execution of arbitrary actions on behalf of the victim within the affected web application. For e-commerce or booking sites, this could result in fraudulent bookings, exposure of customer data, and severe reputational damage. The broad reach of WordPress plugins means a large number of potentially affected websites and users are at risk if the vulnerability is exploited in the wild.

## Recommendation

* Patch CVE-2026-15401 immediately by updating the VikBooking Hotel Booking Engine & PMS plugin for WordPress to version 1.8.14 or later.
* Deploy the Sigma rule "Detects CVE-2026-15401 Exploitation - VikBooking XSS Payload Delivery" to your SIEM to detect attempted exploitation.
* Enable comprehensive web server logging, specifically capturing HTTP POST requests, URI stems, and query parameters, to ensure data is available for the Sigma rule.
* Monitor `webserver` logs for suspicious POST requests to `admin-ajax.php` containing XSS payload patterns in the `vbfX` parameter, as outlined in the detection rule.
