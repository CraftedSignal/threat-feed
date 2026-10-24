---
brief_id: brief-2026-10-24-mollie-craft-commerce-auth-bypass
event_id: brief-2026-10-24-mollie-craft-commerce-auth-bypass
revision: 1
activity_at: "2026-10-24T00:03:43Z"
title: Mollie Craft Commerce webhook authentication bypass (CVE-2026-115937)
slug: 2026-10-mollie-craft-commerce-auth-bypass
description: An authentication bypass vulnerability in the Craft Commerce Mollie integration allows unauthenticated attackers to mark arbitrary transactions as paid by manipulating webhook parameters.
date: "2026-10-24T00:03:43Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:mollie:craft_commerce:*:*:*:*:*:*:*:*
tags:
  - web-application
  - authentication-bypass
  - commerce-vulnerability
vendors:
  - Mollie
products:
  - Craft Commerce (Mollie integration)
cves:
  - id: CVE-2026-115937
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115937
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all web servers running Craft Commerce with the Mollie plugin.
      owner: IT Operations
      due: 24h
      evidence: The vulnerability exists within the Mollie webhook endpoint for Craft Commerce.
  hunt_leads:
    - lead: Search web server access logs for POST requests to the Mollie webhook endpoint containing mismatched parameter identifiers.
      technique_id: T1190
      data_needed:
        - Web server access logs
        - Application logs showing webhook processing
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: An unauthenticated attacker holding any paid Mollie payment ID from the merchant’s account can pair it with any transaction hash.
  mitigation_plan:
    - priority: immediate
      action: Patch the Craft Commerce Mollie plugin once a security update is released by the vendor.
      owner: IT Operations
      addresses: CVE-2026-115937
      evidence: This is a vulnerability in the Mollie webhook endpoint.
---

The Mollie integration for Craft Commerce contains a critical flaw (CVE-2026-115937) in its webhook endpoint. The endpoint fails to verify that the `commerceTransactionHash` and `id` parameters are cryptographically or logically bound to each other. An unauthenticated attacker possessing a valid Mollie payment ID from the merchant's account can pair it with the transaction hash of any other pending order. The system queries Mollie for the status of the supplied payment ID, receives a 'paid' status, and subsequently marks the target transaction as fully paid, regardless of the actual amount remitted.

## Impact
Successful exploitation allows for improper order fulfillment by enabling attackers to complete transactions without submitting valid payment for those specific orders. This can result in unauthorized receipt of goods or services.

## Recommendation
1. Identify all instances of Craft Commerce utilizing the Mollie integration.
2. Audit webhook traffic logs for recurring patterns of mismatched transaction hashes and payment IDs.
3. Monitor for and apply patches provided by the plugin maintainers to enforce parameter validation between the transaction hash and the payment ID.
4. Review commerce logs for transactions marked as 'paid' that lack corresponding legitimate payment records.
