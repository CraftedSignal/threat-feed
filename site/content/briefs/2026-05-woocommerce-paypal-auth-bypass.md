---
title: WooCommerce PayPal Payments Plugin Vulnerable to Order Manipulation and Information Disclosure (CVE-2026-9284)
slug: 2026-05-woocommerce-paypal-auth-bypass
description: The WooCommerce PayPal Payments plugin for WordPress is vulnerable to unauthorized order manipulation and information disclosure due to missing authorization checks on WC-AJAX endpoints, allowing attackers to manipulate order payment flows and exfiltrate sensitive order details (CVE-2026-9284).
date: "2026-05-26T13:34:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - woocommerce
  - wordpress
  - paypal
  - authorization-bypass
  - information-disclosure
vendors:
  - WooCommerce
products:
  - WooCommerce PayPal Payments plugin <= 4.0.1
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials on Web Servers
cves:
  - id: CVE-2026-9284
    cvss: 8.2
    epss: 0.00059
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9284
rules:
  - title: Detect CVE-2026-9284 Exploitation — Unauthorized Access to WooCommerce PayPal Endpoints
    description: Detects CVE-2026-9284 exploitation — unauthorized access to the `ppc-create-order` or `ppc-get-order` WC-AJAX endpoints in the WooCommerce PayPal Payments plugin.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-9284 Exploitation — POST Request to ppc-create-order
    description: Detects CVE-2026-9284 exploitation — HTTP POST request to `ppc-create-order` WC-AJAX endpoint indicating potential unauthorized order creation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The WooCommerce PayPal Payments plugin for WordPress, in versions up to and including 4.0.1, contains a vulnerability (CVE-2026-9284) that allows for unauthorized order manipulation and information disclosure. The vulnerability stems from missing authorization checks on the `ppc-create-order` and `ppc-get-order` WC-AJAX endpoints. By exploiting these missing checks, an attacker can create PayPal orders for arbitrary WooCommerce orders and retrieve PayPal order details without proper authorization. This can lead to attackers manipulating other customers' order payment flows and exfiltrating sensitive order details.

## Attack Chain

1. An unauthenticated attacker identifies a target WooCommerce store using the vulnerable plugin (version <= 4.0.1).
2. The attacker discovers a valid WooCommerce order ID belonging to another customer.
3. The attacker sends a crafted request to the `ppc-create-order` WC-AJAX endpoint, specifying the victim's WooCommerce order ID in the `pay-now` context. The plugin does not validate order ownership, allowing the attacker to associate a new PayPal order with the victim's WooCommerce order.
4. The plugin creates a new PayPal order linked to the victim's WooCommerce order, and writes PayPal metadata to it.
5. The attacker obtains the PayPal order ID associated with the victim's order.
6. The attacker sends a request to the `ppc-get-order` WC-AJAX endpoint, specifying the PayPal order ID.
7. The plugin returns full PayPal order details, including payer information and shipping data, without validating the requester's session.
8. The attacker exfiltrates the sensitive order details, including payer information and shipping data. The attacker could also attempt to modify shipping information, potentially diverting the order.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to manipulate the payment flows of other customers' orders within a WooCommerce store. This includes the potential for exfiltrating sensitive order details such as payer information and shipping data. Attackers could also modify order details, potentially diverting shipments or causing financial harm to both the store owner and their customers.

## Recommendation

*   Upgrade the WooCommerce PayPal Payments plugin to the latest version, which contains a patch for CVE-2026-9284.
*   Monitor web server logs for suspicious POST requests to the `ppc-create-order` and `ppc-get-order` WC-AJAX endpoints (see Sigma rule "Detect CVE-2026-9284 Exploitation — Unauthorized Access to WooCommerce PayPal Endpoints").
*   Implement rate limiting on the `ppc-create-order` and `ppc-get-order` endpoints to mitigate potential abuse.
