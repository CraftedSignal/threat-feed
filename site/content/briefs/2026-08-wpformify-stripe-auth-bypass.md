---
title: Unauthenticated Stripe Credential Modification in WPFormify WordPress Plugin
slug: 2026-08-wpformify-stripe-auth-bypass
description: An unauthenticated vulnerability in the WPFormify plugin allows attackers to overwrite or delete Stripe API credentials via missing capability checks on admin-post.php.
date: "2026-08-05T09:16:35Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - WordPress
products:
  - WPFormify – Stripe Payments with Form and Checkout (<= 1.1.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: This makes it possible for unauthenticated attackers to overwrite the site's Stripe API credentials with attacker-controlled values.
    confidence_band: high
cves:
  - id: CVE-2026-6627
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6627
rules:
  - title: Detect CVE-2026-6627 Exploitation - Unauthenticated Stripe Config Change
    description: Detects unauthorized attempts to access or modify Stripe settings in WPFormify by monitoring POST requests to admin-post.php with internal function parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1565.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Update WPFormify plugin to the latest version to address CVE-2026-6627
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable in versions <= 1.1.1
---

The WPFormify - Stripe Payments with Form and Checkout plugin for WordPress, in versions up to and including 1.1.1, contains a critical authentication bypass vulnerability (CVE-2026-6627). The flaw resides in the wpf_stripe_callback_success() and wpf_stripe_disconnect() functions. These functions, which handle critical Stripe integration settings, are incorrectly hooked to the admin_init action. Because admin_init fires during requests to admin-post.php, and these functions lack necessary capability checks or nonce verification, unauthenticated remote attackers can interact with these endpoints. By sending crafted requests to admin-post.php, an attacker can overwrite existing Stripe API keys with their own, effectively redirecting all customer payments to a malicious account. Alternatively, an attacker may trigger the disconnect function to disrupt the site's payment processing capabilities entirely. This vulnerability poses a high financial risk to any organization using the plugin for payment collection.

## Impact

Successful exploitation allows unauthenticated attackers to hijack payment flows, leading to complete loss of transaction revenue or service disruption. All WordPress sites running WPFormify version 1.1.1 or lower are affected. There is no information provided regarding the total number of victims, but the nature of the vulnerability facilitates direct financial fraud.

## Recommendation

- Update the WPFormify - Stripe Payments with Form and Checkout plugin to the latest version immediately to remediate the missing capability checks.
- Review WordPress audit logs for unexpected POST requests to admin-post.php, specifically those originating from unauthenticated sessions that invoke Stripe-related parameters.
- Audit current Stripe configuration settings in the WordPress admin panel to verify that the configured API keys match authorized merchant account values.
