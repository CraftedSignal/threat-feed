---
title: WordPress Easy PayPal Events & Tickets Plugin Information Disclosure Vulnerability
slug: 2026-05-wordpress-easy-paypal-info-disclosure
description: An information disclosure vulnerability in the Easy PayPal Events & Tickets WordPress plugin (versions 1.3 and earlier) allows unauthenticated attackers to enumerate and retrieve all customer order records via the scan_qr.php endpoint.
date: "2026-05-04T18:16:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - info-disclosure
  - cve-2026-41471
  - unauthenticated
  - enumeration
vendors:
  - WordPress
products:
  - Easy PayPal Events & Tickets plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-41471
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41471
rules:
  - title: Detect Access to scan_qr.php with Iterative Post IDs
    description: Detects unauthenticated requests to the scan_qr.php endpoint with iterative post IDs, indicating potential exploitation of the Easy PayPal Events & Tickets information disclosure vulnerability.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Multiple Requests to scan_qr.php from the same IP
    description: Detects multiple requests to the scan_qr.php endpoint from the same IP address within a short time frame, potentially indicating enumeration attempts.
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

The Easy PayPal Events & Tickets plugin for WordPress, versions 1.3 and earlier, contains an information disclosure vulnerability (CVE-2026-41471). This vulnerability allows unauthenticated attackers to iterate through WordPress post IDs via the `scan_qr.php` endpoint. By sequentially accessing these IDs, attackers can retrieve customer order records stored within the WordPress database. The plugin was officially closed as of March 18, 2026, meaning websites using the plugin prior to this date are vulnerable. This allows for the potential harvesting of sensitive customer data including names, addresses, and purchase histories.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site using the vulnerable Easy PayPal Events & Tickets plugin (version 1.3 or earlier).
2. The attacker crafts a malicious HTTP request targeting the `scan_qr.php` endpoint.
3. The attacker modifies the request to iterate through sequential WordPress post IDs.
4. The server processes the request without proper authentication or authorization checks.
5. The `scan_qr.php` endpoint queries the WordPress database for order records associated with the provided post ID.
6. If a valid order record is found, the server returns the information in the HTTP response.
7. The attacker parses the HTTP response to extract customer order information.
8. The attacker repeats steps 2-7, incrementing the post ID to enumerate all order records.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to retrieve all customer order records stored in the WordPress database. This can lead to the disclosure of sensitive customer information, including names, email addresses, purchase history, and potentially other personal details. The number of affected victims depends on the popularity and usage of the vulnerable plugin. If the database contains financial information the impact could be severe.

## Recommendation

*   Deploy the Sigma rule detecting requests to the scan_qr.php endpoint with iterative post IDs to identify potential exploitation attempts.
*   If still using the Easy PayPal Events & Tickets plugin, remove the plugin, as it was closed as of 2026-03-18.
*   Monitor web server logs for suspicious activity targeting the `scan_qr.php` endpoint.
*   Review the WordPress access logs for requests originating from unusual IP addresses accessing the `scan_qr.php` endpoint.
