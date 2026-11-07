---
brief_id: brief-2026-11-07-woocommerce-priv-esc
event_id: brief-2026-11-07-woocommerce-priv-esc
revision: 1
activity_at: "2026-11-07T14:44:22Z"
title: 'Registration Form for WooCommerce: Privilege escalation vulnerability (CVE-2026-119075)'
slug: 2026-11-woocommerce-priv-esc
description: The Registration Form for WooCommerce plugin for WordPress contains an unauthenticated privilege escalation vulnerability in the checkout registration path, allowing attackers to assign arbitrary roles, including Administrator.
date: "2026-11-07T14:44:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:registration_form_for_woocommerce_project:registration_form_for_woocommerce:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - plugin
  - privilege-escalation
  - web-application
vendors:
  - WordPress
products:
  - Registration Form for WooCommerce (<= 1.1.4)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for unauthenticated attackers to elevate their privileges to Administrator by supplying a user_roles=administrator parameter when creating an account during checkout.
    confidence_band: high
cves:
  - id: CVE-2026-119075
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119075
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Audit WordPress user database for accounts created with Administrator or elevated roles during the checkout process.
      owner: SOC
      due: 24h
      evidence: Unauthenticated attackers can inject a user_roles parameter during the checkout process.
  hunt_leads:
    - lead: Monitor web server access logs for POST requests to checkout endpoints containing user_roles parameter injection.
      technique_id: T1068
      data_needed:
        - Web server access logs (HTTP POST requests to checkout URLs)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The checkout registration path (validate_checkout_fields(), hooked to woocommerce_after_checkout_validation) stores the raw $_POST[user_roles] value.
  mitigation_plan:
    - priority: immediate
      action: Disable user registration via WooCommerce checkout or uninstall the Registration Form for WooCommerce plugin until a security update is applied.
      owner: IT Operations
      addresses: CVE-2026-119075
      evidence: The Registration Form for WooCommerce plugin for WordPress is vulnerable to privilege escalation.
---

Registration Form for WooCommerce versions 1.1.4 and earlier contain a critical privilege escalation vulnerability (CVE-2026-119075). The issue exists within the `FormHandler::validate_checkout_fields()` function, which fails to enforce an allow-list on the `user_roles` parameter during the checkout registration process. This allows an unauthenticated user to inject arbitrary role values, such as 'administrator', into the `woocommerce_new_customer_data` array, resulting in unauthorized account creation with elevated privileges.

## Impact

Successful exploitation allows unauthenticated attackers to gain administrative access to the WordPress site, leading to full site takeover.

## Recommendation

- Update the "Registration Form for WooCommerce" plugin to the latest version once a patch is released.
- Review user account creation logs for suspicious activity involving administrative roles created during the checkout process.
- Audit existing user accounts for unauthorized assignments of the Administrator role.
