---
title: Stripe Webhook Signature Bypass via Empty Secret Enables Unlimited Quota Fraud
slug: 2026-04-stripe-webhook-bypass
description: A vulnerability in the Stripe webhook handler allows an unauthenticated attacker to forge webhook events and credit arbitrary quota to their account without payment, stemming from an empty StripeWebhookSecret and lack of PaymentMethod validation, enabling cross-gateway exploitation.
date: "2026-04-24T15:43:25Z"
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

A critical vulnerability exists in the Stripe webhook handler that allows an unauthenticated attacker to forge webhook events and credit arbitrary quota to their account without making any payment. Disclosed on 2025-04-15 and patched the same day in v0.12.10, the vulnerability stems from three compounding flaws: the Stripe webhook endpoint does not reject requests when `StripeWebhookSecret` is empty (the default), any attacker can compute valid webhook signatures when the HMAC secret is empty…
