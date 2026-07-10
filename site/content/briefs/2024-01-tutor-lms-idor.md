---
title: Tutor LMS WordPress Plugin Insecure Direct Object Reference (CVE-2026-3360)
slug: 2024-01-tutor-lms-idor
description: The Tutor LMS plugin for WordPress is vulnerable to an Insecure Direct Object Reference (IDOR), allowing unauthenticated attackers to overwrite billing profiles of users with incomplete orders.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - idor
  - cve-2026-3360
  - tutor-lms
vendors:
  - Tutor LMS
products:
  - Tutor LMS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-3360
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3360
rules:
  - title: Tutor LMS Insecure Order ID Access
    description: Detects potential exploitation of the Tutor LMS IDOR vulnerability by monitoring POST requests to admin-ajax.php with the pay_incomplete_order action.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Tutor LMS Billing Profile Update
    description: Detects potential unauthorized billing profile updates in Tutor LMS by monitoring for POST requests indicating billing modifications.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1555.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Tutor LMS plugin, a widely used eLearning solution for WordPress, contains an Insecure Direct Object Reference (IDOR) vulnerability (CVE-2026-3360) affecting versions up to and including 3.9.7. This flaw resides within the `pay_incomplete_order()` function, which lacks proper authentication and authorization checks. The function processes user orders based on the `order_id` parameter, without validating the requester's identity or their ownership of the order. The `_tutor_nonce` is exposed on public frontend pages. An unauthenticated attacker can exploit this vulnerability to modify the billing information of any user who has an incomplete manual order within the Tutor LMS system. This is achieved by sending a specially crafted POST request containing a valid, but potentially guessed or enumerated, `order_id`.

## Attack Chain

1.  Attacker identifies a WordPress site using a vulnerable version (<= 3.9.7) of the Tutor LMS plugin.
2.  Attacker enumerates or guesses valid `order_id` values for incomplete manual orders. These IDs are integers and could be found by observing order numbers.
3.  Attacker crafts a POST request to the `/wp-admin/admin-ajax.php` endpoint, targeting the `pay_incomplete_order` action.
4.  The POST request includes the vulnerable `order_id` parameter and malicious billing data (name, email, phone, address). The request also requires a valid `_tutor_nonce`.
5.  The server-side `pay_incomplete_order()` function processes the request without verifying the attacker's identity or authorization to modify the target user's billing information.
6.  The function retrieves the order data associated with the provided `order_id`.
7.  The function uses `$order_data->user_id` and writes the attacker-supplied billing details to the profile of the order owner.
8.  The targeted user's billing profile is updated with the attacker's data, potentially leading to account takeover or financial fraud.

## Impact

Successful exploitation of CVE-2026-3360 allows unauthenticated attackers to overwrite sensitive billing information associated with user accounts within a WordPress site using the vulnerable Tutor LMS plugin. The potential impact includes unauthorized modification of user profiles, which can facilitate phishing attacks, identity theft, or financial fraud if the compromised billing information is linked to payment methods. Since the vulnerability exists in a plugin designed for online courses, the targeted sectors are likely education, training, and e-learning platforms.

## Recommendation

*   Upgrade the Tutor LMS plugin to the latest version, which includes a patch for CVE-2026-3360, to remediate the vulnerability.
*   Implement the Sigma rule `Tutor LMS Insecure Order ID Access` to detect attempts to exploit this vulnerability by monitoring for suspicious POST requests to the `admin-ajax.php` endpoint.
*   Implement the Sigma rule `Tutor LMS Billing Profile Update` to detect unauthorized billing profile updates via the vulnerable endpoint.
*   Monitor web server logs for POST requests to `/wp-admin/admin-ajax.php` with the `action` parameter set to `pay_incomplete_order` and investigate any unexpected activity.
