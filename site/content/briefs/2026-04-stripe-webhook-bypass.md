---
title: Stripe Webhook Signature Bypass via Empty Secret Enables Unlimited Quota Fraud
slug: 2026-04-stripe-webhook-bypass
description: A vulnerability in the Stripe webhook handler allows an unauthenticated attacker to forge webhook events and credit arbitrary quota to their account without payment, stemming from an empty StripeWebhookSecret and lack of PaymentMethod validation, enabling cross-gateway exploitation.
date: "2026-04-24T15:43:25Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - stripe
  - webhook
  - signature-bypass
  - quota-fraud
vendors:
  - Stripe
products:
  - Stripe Webhook
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-xff3-5c9p-2mr4
  - https://docs.stripe.com/webhooks#verify-official-libraries
  - https://docs.stripe.com/checkout/fulfillment#async-payment-methods
  - https://cwe.mitre.org/data/definitions/345.html
  - https://cwe.mitre.org/data/definitions/1188.html
rules:
  - title: Detect Forged Stripe Webhook Request
    description: Detects potential attempts to exploit the Stripe webhook signature bypass vulnerability by monitoring requests to the webhook endpoint with suspicious signatures.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Stripe Webhook Request with missing signature
    description: Detects potential attempts to exploit the Stripe webhook signature bypass vulnerability by monitoring requests to the webhook endpoint with missing signatures.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability exists in the Stripe webhook handler that allows an unauthenticated attacker to forge webhook events and credit arbitrary quota to their account without making any payment. Disclosed on 2025-04-15 and patched the same day in v0.12.10, the vulnerability stems from three compounding flaws: the Stripe webhook endpoint does not reject requests when `StripeWebhookSecret` is empty (the default), any attacker can compute valid webhook signatures when the HMAC secret is empty, and the `Recharge` function does not validate that the order's `PaymentMethod` matches the callback source. This enables cross-gateway exploitation where orders created via any payment method can be fulfilled through a forged Stripe webhook. This vulnerability allows for financial fraud through unlimited API quota acquisition without payment.

## Attack Chain

1.  Attacker registers a user account on the target platform.
2.  Attacker calls `POST /api/user/pay` to create an Epay top-up order, setting the `amount`. The order is stored with a `pending` status.
3.  Attacker queries `GET /api/user/topup/self` to retrieve the `trade_no` of the pending order.
4.  Attacker computes an `HMAC-SHA256` signature with an empty key over a crafted `checkout.session.completed` payload. This payload contains the stolen `trade_no` as the `client_reference_id`.
5.  Attacker sends a `POST` request to `/api/stripe/webhook` with the forged payload and a crafted `Stripe-Signature` header.
6.  The server verifies the signature, which passes because the `StripeWebhookSecret` is empty.
7.  The server calls the `Recharge()` function, which finds the Epay order by `trade_no`, marks the order as `success`, and credits the attacker's account with the full quota.
8.  The attacker repeats steps 2-6 indefinitely to accumulate unlimited credits, leading to financial fraud.

## Impact

This vulnerability allows attackers to obtain unlimited API quota without payment, leading to financial fraud. The operator of the vulnerable system faces financial losses due to fraudulent quota consumption against upstream AI providers such as OpenAI, Anthropic, and Google. The fraudulent top-ups can appear as normal transactions in system logs, making detection challenging. Due to the default insecure configuration, virtually all deployments with any payment method enabled are vulnerable, creating a wide exposure.

## Recommendation

*   Set `StripeWebhookSecret` to a non-empty value to prevent empty-key HMAC forgery, mitigating the primary attack vector (Flaw 1).
*   Apply a reverse proxy (Nginx, Caddy, etc.) to deny access to `/api/stripe/webhook` if Stripe is not configured, as a temporary workaround.
*   Deploy the Sigma rule `Detect Forged Stripe Webhook Request` to identify potential exploitation attempts by monitoring requests to the webhook endpoint with empty secrets or invalid signatures.
*   Upgrade to v0.12.10 immediately, as it addresses all three flaws completely.
