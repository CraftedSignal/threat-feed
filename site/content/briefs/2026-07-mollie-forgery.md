---
title: Sylius Mollie Plugin Payment Status Forgery Vulnerability
slug: 2026-07-mollie-forgery
description: The Sylius Mollie Plugin is susceptible to an unauthenticated payment status forgery via the webhook handler, allowing attackers to mark arbitrary orders as paid by reusing valid payment IDs.
date: "2026-07-31T19:29:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - web-application
  - e-commerce
  - cve-2026-68500
  - logic-vulnerability
vendors:
  - Sylius
products:
  - Sylius Mollie Plugin
cves:
  - id: CVE-2026-68500
    cvss: 7.5
    epss: 0.00382
references:
  - https://github.com/advisories/GHSA-rc52-c4hv-w89p
rules:
  - title: Detect Mollie Webhook Forgery Attempts
    description: Detects potential mass-exploitation attempts by monitoring for a high volume of POST requests to the Mollie webhook endpoint from a single source
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

The Sylius Mollie Plugin contains a critical logic flaw (CVE-2026-68500) in the payment webhook controller that allows unauthenticated attackers to forge payment status updates. The vulnerability exists in the `sylius_mollie_shop_payment_webhook` endpoint (`/{_locale}/update-payment`). This endpoint accepts an `id` parameter (Mollie payment ID) and an `orderId` parameter without validating that the provided payment ID actually belongs to the specified order.

An attacker can exploit this by obtaining a valid, successful Mollie payment ID from their own transaction (e.g., a minimal value purchase) and submitting it to the webhook along with the sequential ID of a victim's pending order. The application incorrectly marks the victim's order as paid, enabling unauthorized fulfillment without corresponding financial settlement. Given that Sylius order IDs are typically sequential, this flaw allows for mass exploitation and financial impact on merchants. The vulnerability affects plugin versions prior to 2.2.8, 3.2.4, and 3.3.1.

## Attack Chain

1. Attacker performs a legitimate purchase on the target e-commerce site to obtain a valid, successful `id` (Mollie payment reference).
2. Attacker identifies a sequence of target `orderId` values (e.g., sequential integers) for pending orders in the store.
3. Attacker crafts an HTTP POST request to the endpoint `/{_locale}/update-payment`.
4. Attacker inserts the legitimate Mollie payment `id` obtained in step 1 into the `id` request parameter.
5. Attacker iterates through the target `orderId` values in the `orderId` request parameter.
6. The backend processes the malicious webhook, fails to correlate the payment to the order, and updates the payment status to "completed" in the database.
7. The attacker receives an HTTP 200 response from the server, indicating successful processing.
8. The merchant's order management system marks the victim's order as paid, triggering unauthorized inventory fulfillment or service delivery.

## Impact

Successful exploitation results in significant financial loss for merchants, as attackers can bypass payment verification to obtain goods or services for free. Because the endpoint lacks authentication, CSRF protections, or rate limiting, an attacker can programmatically iterate through large numbers of orders, causing widespread fraudulent state changes across the entire store's transaction database.

## Recommendation

- Upgrade the `composer/sylius/mollie-plugin` to versions 2.2.8, 3.2.4, or 3.3.1 immediately to incorporate the mandatory binding verification between Mollie IDs and order records.
- If immediate patching is not possible, implement the provided decorator pattern in `src/Controller/Mollie/SecurePaymentWebhookController.php` to perform pre-validation of the `orderId` against the stored `payment_mollie_id` before the native controller processes the request.
- Monitor web server logs for high-frequency POST requests to the `/{_locale}/update-payment` endpoint originating from single IP addresses, which may indicate automated status forgery attempts.
- Ensure that the web server configuration for this path includes strict rate limiting to mitigate the risk of mass automated order status modification.
