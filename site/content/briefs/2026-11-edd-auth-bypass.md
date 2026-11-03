---
brief_id: brief-2026-11-03-edd-auth-bypass
event_id: brief-2026-11-03-edd-auth-bypass
revision: 1
activity_at: "2026-11-03T05:54:40Z"
title: 'Easy Digital Downloads: Authentication bypass in PayPal checkout (CVE-2026-120538)'
slug: 2026-11-edd-auth-bypass
description: The Easy Digital Downloads WordPress plugin is vulnerable to authentication bypass and account takeover due to insecure association of guest checkout orders with existing user accounts based on email address.
date: "2026-11-03T05:54:40Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against NVD disclosure
cpes:
  - cpe:2.3:a:easydigitaldownloads:easy_digital_downloads:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - authentication-bypass
vendors:
  - Easy Digital Downloads
products:
  - Easy Digital Downloads (<= 3.7.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
    evidence: An unauthenticated attacker who starts a guest checkout using an administrator's email address (where that administrator has no existing EDD customer record) and completes the PayPal purchase flow therefore receives an authenticated session as that administrator.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550.001
    technique_name: Application Access Token
    evidence: The PayPal capture sink PurchaseUser::maybe_log_in_after_capture() ... issued an authenticated session with wp_set_auth_cookie().
    confidence_band: high
cves:
  - id: CVE-2026-120538
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120538
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Easy Digital Downloads plugin to the latest version.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability CVE-2026-120538 affects versions <= 3.7.2
  hunt_leads:
    - lead: Search WordPress access logs for unusual login events correlated with PayPal checkout POST requests.
      technique_id: T1550.001
      data_needed:
        - Web server logs
        - WordPress authentication logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploitation occurs through standard PayPal checkout flows, leading to authenticated session creation.
---

The Easy Digital Downloads (EDD) plugin for WordPress contains an authentication bypass vulnerability (CVE-2026-120538) affecting versions 3.7.2 and earlier. During guest checkout via PayPal, the plugin incorrectly trusts the provided email address to associate a guest order with an existing WordPress user account. The function `edd_get_purchase_form_user()` binds the order to an existing user if the provided email matches, and `PurchaseUser::maybe_log_in_after_capture()` subsequently calls `wp_set_auth_cookie()` to grant an authenticated session to that user. An unauthenticated attacker can exploit this by using a target administrator's email address during the PayPal purchase flow.

## Attack Chain

1. Attacker initiates a guest checkout session within the WordPress site using the target administrator's email address.
2. The site application executes `edd_get_purchase_form_user()`, which identifies a match for the administrator's email in the WordPress user table.
3. The order's `user_id` is updated to reflect the matched administrator's ID.
4. The attacker completes the PayPal checkout process.
5. The `PurchaseUser::maybe_log_in_after_capture()` function processes the payment capture.
6. The plugin retrieves the user by the supplied email and validates the `user_id` match.
7. The system automatically issues an authentication cookie for the administrator account via `wp_set_auth_cookie()`.

## Impact

Successful exploitation results in full administrative account takeover of the WordPress site.

## Recommendation

* Patch the Easy Digital Downloads plugin immediately. Upgrade to a version beyond 3.7.2.
* Audit WordPress user session logs for anomalous login activity originating from recent PayPal checkout events.
* Monitor for unexpected creation of administrative accounts or changes to existing user privileges.
