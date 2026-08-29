---
title: Privilege Escalation in Custom User Registration Fields for WooCommerce Plugin
slug: 2026-08-woocommerce-privilege-escalation
description: An unauthenticated privilege escalation vulnerability (CVE-2026-15369) in Custom User Registration Fields for WooCommerce allows remote attackers to assign arbitrary user roles, including Administrator, by injecting malicious parameters during the checkout process.
date: "2026-08-29T21:41:54Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:custom_user_registration_fields_for_woocommerce_project:custom_user_registration_fields_for_woocommerce:*:*:*:*:*:wordpress:*:*
tags:
  - web
  - wordpress
  - privilege-escalation
  - woocommerce
vendors:
  - WordPress
products:
  - Custom User Registration Fields for WooCommerce (<= 2.2.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for unauthenticated attackers to elevate their privileges to Administrator by creating an account during checkout with a modified JSON body specifying administrator as the desired role.
    confidence_band: high
cves:
  - id: CVE-2026-15369
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15369
rules:
  - title: Detects CVE-2026-15369 Exploitation - Unauthorized Role Assignment in WooCommerce Store API
    description: Detects potential exploitation attempts targeting the WooCommerce Store API where an unauthenticated user injects role-changing parameters during checkout.
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
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch plugin version to > 2.2.3
      owner: IT Operations
      due: 24h
      evidence: Source confirms vulnerability in <= 2.2.3
  mitigation_plan:
    - priority: immediate
      action: Disable 'User Role Selection' in WooCommerce plugin settings
      owner: IT Operations
      addresses: CVE-2026-15369
      evidence: 'Source states: Note: The exploit requires the User Role Selection setting to be enabled.'
---

The Custom User Registration Fields for WooCommerce plugin for WordPress is vulnerable to a critical privilege escalation flaw identified as CVE-2026-15369. The vulnerability affects versions up to and including 2.2.3. It stems from improper input validation within the WooCommerce Store API. Specifically, the af_reg_checkout_data_to_order_meta_data_block function accepts a user-controlled parameter, afreg_select_user_role, via the /wc/store/v1/checkout endpoint. 

When the "User Role Selection" feature is enabled in the plugin settings, this input is persisted into order metadata. The af_reg_custom_order_processing_function, which executes during the woocommerce_thankyou hook, retrieves this unvalidated value and passes it directly to the WP_User::add_role() function. Because there is no check against an allowlist of permitted roles, an unauthenticated attacker can manipulate the checkout request to elevate their account permissions to Administrator or other sensitive roles. This flaw poses a significant risk to the integrity and confidentiality of affected WordPress installations.

## Impact

Successful exploitation allows unauthenticated attackers to gain administrative access to a compromised WordPress site. This leads to full administrative control, enabling the attacker to execute arbitrary code via plugin/theme installation, modify site content, exfiltrate user databases, or deploy persistent backdoors. Given the ubiquity of WooCommerce, this vulnerability impacts any e-commerce site running the affected plugin version with the specific feature enabled.

## Recommendation

Prioritized actions for detection engineering and security operations teams:
- Update the "Custom User Registration Fields for WooCommerce" plugin to a patched version beyond 2.2.3 immediately.
- If an update is not immediately available, disable the "User Role Selection" feature in the plugin settings to mitigate the primary vector of this vulnerability.
- Review web server access logs for anomalous POST requests to the /wc/store/v1/checkout endpoint, particularly those containing suspicious strings or unexpected JSON parameters in the request body.
