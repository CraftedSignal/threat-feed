---
title: 'CVE-2026-3576: Planyo WordPress Plugin Vulnerable to SSRF and LFI'
slug: 2026-07-planyo-wordpress-ssrf-lfi
description: The Planyo Online Reservation System plugin for WordPress, in all versions up to and including 3.0, is vulnerable to Server-Side Request Forgery (SSRF) leading to Local File Inclusion (LFI), allowing an unauthenticated attacker to exploit the `ulap.php` file by supplying a `file://` URL that bypasses the host allowlist, reading arbitrary local files on the server and retrieving their contents in the HTTP response, potentially disclosing sensitive data.
date: "2026-07-11T05:20:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - ssrf
  - lfi
  - web-application
  - cve
vendors:
  - Planyo
  - WordPress
products:
  - Planyo Online Reservation System plugin <= 3.0
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: This makes it possible for unauthenticated attackers to supply a file:// URL (e.g., file://localhost/etc/passwd) [...] allowing the attacker to read arbitrary local files on the server and have their contents returned in the HTTP response.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Planyo Online Reservation System plugin for WordPress is vulnerable to Server-Side Request Forgery leading to Local File Inclusion in all versions up to, and including, 3.0. The ulap.php file acts as an AJAX proxy and is directly accessible without WordPress bootstrapping or any authentication.
    confidence_band: high
cves:
  - id: CVE-2026-3576
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3576
rules:
  - title: Detects CVE-2026-3576 Exploitation - Planyo WordPress Plugin SSRF/LFI
    description: Detects CVE-2026-3576 exploitation by identifying HTTP POST requests to the Planyo WordPress plugin's ulap.php endpoint with a file://localhost/ URI in the query string, indicative of SSRF leading to LFI.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1005
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

The Planyo Online Reservation System plugin for WordPress, in all versions up to and including 3.0, contains a critical Server-Side Request Forgery (SSRF) vulnerability, identified as CVE-2026-3576, which can be leveraged for Local File Inclusion (LFI). The `ulap.php` file, functioning as an AJAX proxy, is directly accessible without requiring WordPress bootstrapping or any authentication. This vulnerability arises because the `send_http_post()` function validates the host of a provided URL against an allowlist that includes 'localhost' but critically fails to validate the URL scheme or protocol. This oversight allows unauthenticated attackers to supply a `file://` URL, such as `file://localhost/etc/passwd`, which bypasses the host allowlist check because `parse_url()` correctly identifies 'localhost' as the host. The malicious URL is then processed by `curl_init()` or `fopen()`, both of which support the `file://` protocol, enabling the attacker to read arbitrary local files on the server and receive their contents in the HTTP response. This flaw can lead to the disclosure of highly sensitive information, including system configuration files like `/etc/passwd` and WordPress specific credentials in `wp-config.php`.

## Attack Chain

1. An unauthenticated attacker crafts a malicious HTTP POST request targeting the `ulap.php` endpoint of a vulnerable Planyo WordPress plugin installation.
2. The POST request includes a parameter containing a specially formatted `file://` URL, such as `file://localhost/etc/passwd` or `file://localhost/var/www/html/wp-config.php`.
3. The `send_http_post()` function within `ulap.php` receives this URL and uses `parse_url()` to extract the host, which is 'localhost'.
4. The extracted 'localhost' value successfully matches an entry in the plugin's internal host allowlist, allowing the request to proceed.
5. Crucially, the plugin fails to validate or restrict the URL scheme, allowing the `file://` protocol to pass through the validation.
6. The complete `file://` URL is then passed to either `curl_init()` or `fopen()` functions, which interpret it as a request to access a local file.
7. The server-side function reads the content of the specified local file (e.g., `/etc/passwd` or `wp-config.php`).
8. The contents of the arbitrary local file are returned in the HTTP response body to the attacker, achieving local file inclusion and data disclosure.

## Impact

Successful exploitation of CVE-2026-3576 allows unauthenticated attackers to read arbitrary files on the compromised server. This can lead to the disclosure of highly sensitive system information like `/etc/passwd`, which contains user account details. More critically for WordPress installations, attackers can exfiltrate `wp-config.php`, exposing database credentials, authentication unique keys, and salts, granting them potential access to the WordPress database. This could escalate to full site compromise, data manipulation, or further attacks on other systems using the exposed credentials. The vulnerability affects all Planyo Online Reservation System plugin versions up to and including 3.0, potentially exposing a wide range of WordPress sites.

## Recommendation

* Patch CVE-2026-3576 immediately by updating the Planyo Online Reservation System plugin for WordPress to a version greater than 3.0.
* Deploy the Sigma rule "Detects CVE-2026-3576 Exploitation - Planyo WordPress Plugin SSRF/LFI" to your SIEM and configure your web server logs to capture `cs-uri-stem` and `cs-uri-query` for accurate detection.
* Monitor web server access logs for HTTP POST requests to `/wp-content/plugins/planyo/ulap.php` containing `file://localhost/` within the query parameters.
