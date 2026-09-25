---
title: Privilege Escalation in Knit Pay WordPress Plugin
slug: 2026-09-knit-pay-privilege-escalation
description: The Knit Pay WordPress plugin allows authenticated users to achieve privilege escalation to administrator via insecure role assignment handled by the Gravity Forms integration.
date: "2026-09-25T10:52:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:knitpay:knit_pay_-_cashfree,_instamojo,_razorpay,_paypal_and_more:*:*:*:*:*:wordpress:*:*
vendors:
  - Knit Pay
products:
  - Knit Pay – Cashfree, Instamojo, Razorpay, PayPal and more (<= 9.6.1.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers, with Subscriber-level access and above, to elevate their privileges to administrator by tampering with the hidden role field value.
    confidence_band: high
cves:
  - id: CVE-2026-89426
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89426
rules:
  - title: Detects CVE-2026-89426 Exploitation - Privilege Escalation via Knit Pay Plugin
    description: Detects suspicious POST requests to WordPress that include parameters commonly used by Gravity Forms and the Knit Pay plugin, specifically looking for indicators of role modification attempts in form submissions.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Knit Pay plugin to latest version post-9.6.1.0.
      owner: IT Operations
      due: 24h
      evidence: Source explicitly identifies version 9.6.1.0 as the vulnerable cutoff.
  enrichment_needed:
    - item: Identify all WordPress sites in the environment running Knit Pay.
      owner: SOC
      reason: Asset discovery to determine exposure.
      evidence: NVD listing.
  mitigation_plan:
    - priority: immediate
      action: Disable Gravity Forms integration for Knit Pay until patch is applied.
      owner: IT Operations
      addresses: CVE-2026-89426
      evidence: Vulnerability depends on Gravity Forms feed configuration.
---

The Knit Pay plugin for WordPress (versions 9.6.1.0 and earlier) contains a critical privilege escalation vulnerability. The flaw resides within the `maybe_update_user_role()` function, which processes user role updates based on Gravity Forms submission data. Specifically, the plugin uses the `user_role_field_id` configuration to read a requested role from form input and passes this value directly to the `WP_User::set_role()` function without validating it against an allowlist. 

This enables an authenticated user, including those with minimal Subscriber-level access, to manipulate the submitted form data to include an administrator role. Because the plugin processes $0 orders synchronously and assigns roles to the `created_by` user if no other account is resolved, an attacker can submit a crafted form to unilaterally elevate their own privileges. This vulnerability exposes sites to full administrative account takeover by any authenticated user who can submit a configured Gravity Forms form using the vulnerable plugin component.

## Impact

Successful exploitation allows any authenticated user (e.g., a standard Subscriber) to gain full administrative privileges on the target WordPress site. This provides the attacker complete control over the site configuration, content, plugins, and user database, leading to potential site-wide compromise, data exfiltration, or further malware deployment.

## Recommendation

- Update the Knit Pay WordPress plugin to the version released after 9.6.1.0 immediately to patch CVE-2026-89426.
- Review all existing Gravity Forms feeds integrated with Knit Pay to ensure no hidden user role fields are exposed to unauthorized users.
- Audit existing user accounts for unexpected elevation to the 'administrator' role since the implementation of the plugin.
