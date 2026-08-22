---
title: Unauthenticated Checkout Price Bypass in Advanced Product Fields for WooCommerce
slug: 2026-08-woocommerce-addon-bypass
description: The Advanced Product Fields for WooCommerce plugin for WordPress is vulnerable to improper input validation, allowing unauthenticated users to bypass mandatory paid add-ons during checkout.
date: "2026-08-22T15:30:55Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - WordPress
products:
  - Advanced Product Fields (Product Addons) for WooCommerce
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to bypass required paid addons and complete purchases at the base product price only
    confidence_band: high
cves:
  - id: CVE-2026-2996
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-2996
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Advanced Product Fields for WooCommerce to version 1.6.22 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-2996 indicates vulnerability in versions up to 1.6.21
  mitigation_plan:
    - priority: immediate
      action: Review WooCommerce cart transaction history for pricing discrepancies
      owner: SOC
      addresses: CVE-2026-2996
      evidence: Exploitation results in purchasing products at base price only
---

The Advanced Product Fields (Product Addons) for WooCommerce plugin for WordPress is susceptible to a logic flaw within the 'validate_cart_data' function, impacting all versions up to and including 1.6.21. This vulnerability stems from improper input validation, which can be exploited by unauthenticated attackers to manipulate the checkout process. By crafting specific requests, an attacker can bypass the validation requirements for mandatory paid product add-ons. Consequently, users can complete purchases at the base product price, effectively circumventing the intended pricing structure and causing financial loss to the merchant. While a partial patch was introduced in version 1.6.19, the vulnerability persists in version 1.6.21, necessitating an immediate update to the latest available patched version.

## Impact

Successful exploitation of this flaw allows attackers to purchase products without paying for required add-ons, resulting in direct revenue loss for store operators. Given that this exploit is accessible to unauthenticated users, it poses a significant risk to any e-commerce site using the affected plugin for variable product pricing.

## Recommendation

* Update the Advanced Product Fields (Product Addons) for WooCommerce plugin to the latest version beyond 1.6.21 immediately.
* Review WooCommerce order logs for inconsistencies where the total cart value is significantly lower than the sum of base product costs and required add-on configurations.
* Enable verbose logging for the checkout process and monitor for anomalous HTTP POST requests to the WooCommerce cart validation endpoints.
