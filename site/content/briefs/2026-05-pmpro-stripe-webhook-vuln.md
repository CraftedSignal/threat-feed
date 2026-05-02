---
title: Paid Memberships Pro Plugin Vulnerability Allows Unauthorized Stripe Webhook Modification
slug: 2026-05-pmpro-stripe-webhook-vuln
description: The Paid Memberships Pro plugin for WordPress is vulnerable to unauthorized modification of Stripe webhook configurations due to missing capability checks, allowing authenticated attackers with Subscriber-level access to disrupt payment processing.
date: "2026-05-02T12:16:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - stripe
  - webhook
  - vulnerability
  - plugin
vendors:
  - Stripe
  - WordPress
products:
  - Paid Memberships Pro plugin
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Persistence
    technique_id: T1210
    technique_name: Exploitation of Web Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1210
    technique_name: Exploitation of Web Application
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1210
    technique_name: Exploitation of Web Application
cves:
  - id: CVE-2026-4100
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4100
rules:
  - title: Detect Suspicious PMPro Stripe Webhook AJAX Requests
    description: Detects suspicious AJAX requests to modify Stripe webhooks in Paid Memberships Pro, indicating potential exploitation of CVE-2026-4100.
    platform: sigma
    severity: high
    tactics:
      - impact
      - privilege_escalation
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
  - title: Detect PMPro Stripe Webhook AJAX Requests from Non-Admin IPs
    description: Detects AJAX requests to modify Stripe webhooks in Paid Memberships Pro originating from IP addresses not associated with administrative users, indicating potential unauthorized activity.
    platform: sigma
    severity: medium
    tactics:
      - impact
      - privilege_escalation
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Paid Memberships Pro plugin, a popular WordPress plugin for managing paid subscriptions, contains a vulnerability (CVE-2026-4100) that allows authenticated attackers with minimal privileges (Subscriber-level access) to manipulate Stripe webhook configurations. This flaw exists in versions up to and including 3.6.5 due to missing capability checks on specific AJAX handlers. An attacker exploiting this vulnerability can delete, create, or rebuild the site's Stripe webhook, leading to significant disruptions in payment processing, subscription renewal synchronization, cancellation handling, and management of failed payments. This vulnerability puts revenue streams and customer relationships at risk for any organization using the affected plugin versions.

## Attack Chain

1. An attacker gains Subscriber-level access to the WordPress site, either through registration or compromised credentials.
2. The attacker crafts a malicious AJAX request targeting the `wp_ajax_pmpro_stripe_create_webhook` endpoint.
3. Alternatively, the attacker crafts a malicious AJAX request to the `wp_ajax_pmpro_stripe_delete_webhook` endpoint.
4. Or, the attacker crafts a malicious AJAX request to the `wp_ajax_pmpro_stripe_rebuild_webhook` endpoint.
5. Due to missing capability checks, the server processes the request without proper authorization.
6. The Stripe webhook configuration is modified, deleted, or rebuilt based on the attacker's request.
7. Legitimate payment processing and subscription management processes fail due to the altered webhook configuration.
8. The attacker effectively disrupts the site's ability to collect payments and manage subscriptions.

## Impact

Successful exploitation of this vulnerability allows an attacker to completely disrupt a WordPress site's payment processing and subscription management functionalities. This can result in significant financial losses due to interrupted sales and subscription renewals. Furthermore, the disruption can damage customer trust and lead to churn as users experience issues with their subscriptions. The vulnerability affects all sites using Paid Memberships Pro plugin versions up to 3.6.5.

## Recommendation

*   Immediately update the Paid Memberships Pro plugin to the latest version to patch CVE-2026-4100.
*   Monitor WordPress web server logs for POST requests to `/wp-admin/admin-ajax.php` with the `action` parameter set to `pmpro_stripe_create_webhook`, `pmpro_stripe_delete_webhook`, or `pmpro_stripe_rebuild_webhook` using the "Detect Suspicious PMPro Stripe Webhook AJAX Requests" Sigma rule.
*   Review user roles and permissions to minimize the number of users with Subscriber-level access as a temporary mitigation.
