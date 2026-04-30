---
title: ProfilePress WordPress Plugin Membership Payment Bypass Vulnerability
slug: 2026-04-profilepress-bypass
description: The ProfilePress WordPress plugin before 4.16.12 is vulnerable to an unauthorized membership payment bypass, allowing authenticated attackers to obtain paid memberships without payment by manipulating subscription IDs during checkout.
date: "2026-04-04T09:16:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - vulnerability
  - membership
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-3445
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3445
rules:
  - title: Detect ProfilePress Membership Bypass Attempt
    description: Detects attempts to exploit the ProfilePress membership bypass vulnerability by monitoring for POST requests to admin-ajax.php with the ppress_process_checkout action.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect ProfilePress Membership Bypass Attempt - change_plan_sub_id Parameter
    description: Detects attempts to exploit the ProfilePress membership bypass vulnerability by monitoring for POST requests to admin-ajax.php with the ppress_process_checkout action and the presence of change_plan_sub_id in the query string.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The ProfilePress plugin for WordPress, specifically the "Paid Membership Plugin, Ecommerce, User Registration Form, Login Form, User Profile & Restrict Content" version 4.16.11 and earlier, contains a vulnerability (CVE-2026-3445) that allows authenticated attackers to bypass membership payment requirements. This flaw stems from a missing ownership verification on the `change_plan_sub_id` parameter within the `process_checkout()` function. An attacker with subscriber-level access can exploit this by referencing another user's active subscription during the checkout process. This manipulation affects proration calculations, ultimately enabling the attacker to obtain paid lifetime membership plans without submitting legitimate payment. This vulnerability is triggered via the `ppress_process_checkout` AJAX action, making it critical for defenders to implement appropriate detection and mitigation strategies.

## Attack Chain

1. An attacker registers a new account on the WordPress site with the vulnerable ProfilePress plugin installed, obtaining subscriber-level access.
2. The attacker identifies a valid, active subscription ID belonging to another user within the ProfilePress system.
3. The attacker initiates the purchase of a paid membership plan (e.g., a lifetime membership).
4. During the checkout process, the attacker intercepts the HTTP request sent to the `ppress_process_checkout` AJAX action.
5. The attacker modifies the `change_plan_sub_id` parameter within the request, replacing the expected value with the subscription ID of the other user.
6. The server-side `process_checkout()` function fails to properly validate the ownership of the provided `change_plan_sub_id`.
7. Due to the manipulated `change_plan_sub_id`, the proration calculations are skewed, resulting in a significantly reduced or zeroed payment amount.
8. The attacker completes the checkout process without making a legitimate payment and is granted access to the paid membership plan.

## Impact

Successful exploitation of CVE-2026-3445 allows attackers to bypass payment requirements and gain unauthorized access to premium content and features offered through the ProfilePress plugin. This can result in significant revenue loss for website owners relying on paid memberships. The number of affected websites is potentially large, given the popularity of WordPress and the ProfilePress plugin. This vulnerability could also damage the reputation of the affected website and erode trust among legitimate paying members.

## Recommendation

*   Upgrade to ProfilePress version 4.16.12 or later to patch CVE-2026-3445 (reference: vulnerability description).
*   Deploy the Sigma rule `Detect ProfilePress Membership Bypass Attempt` to your SIEM and tune for your environment to detect potential exploitation attempts by monitoring for the use of the `ppress_process_checkout` AJAX action with suspicious `change_plan_sub_id` values (reference: Sigma rule).
*   Monitor web server logs for POST requests to the `/wp-admin/admin-ajax.php` endpoint with the `action` parameter set to `ppress_process_checkout` to identify potential exploit attempts (reference: Attack Chain).
