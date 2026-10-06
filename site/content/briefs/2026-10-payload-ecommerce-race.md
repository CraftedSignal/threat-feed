---
title: Duplicate Order Processing in Payload Ecommerce Stripe Adapter
slug: 2026-10-payload-ecommerce-race
description: A logic flaw in the @payloadcms/plugin-ecommerce Stripe payment adapter allows order confirmations to be processed multiple times, posing a risk of duplicate fulfillment.
date: "2026-10-06T18:47:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:payload_cms:payloadcms_plugin_ecommerce:*:*:*:*:*:*:*:*
vendors:
  - Payload CMS
products:
  - payloadcms/plugin-ecommerce (< 3.90.0, >= 4.0.0-canary.0 < 4.0.0-canary.34)
cves:
  - id: CVE-2026-105850
references:
  - https://github.com/advisories/GHSA-8r29-2mp2-pmrw
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development Team
  mitigation_plan:
    - priority: immediate
      action: Upgrade @payloadcms/plugin-ecommerce to version 3.90.0 or 4.0.0-canary.34
      owner: Development Team
      addresses: CVE-2026-105850
      evidence: Users should upgrade Payload packages to >= 3.90.0 or >= 4.0.0-canary.34.
---

Payload CMS has disclosed a vulnerability in the @payloadcms/plugin-ecommerce package that impacts the handling of Stripe payment adapter events. Under specific conditions, an order confirmation can be processed more than once, potentially leading to duplicate transaction processing or redundant order fulfillment. This issue affects versions prior to 3.90.0 and certain 4.0.0-canary releases. This flaw is identified as CVE-2026-105850 and relates to the atomicity or idempotency of the confirmation processing logic within the plugin.

## Impact

Successful exploitation of this logic flaw can result in financial discrepancies, unauthorized duplicate orders, and inventory or fulfillment errors for affected e-commerce deployments. The scope is limited to systems utilizing the @payloadcms/plugin-ecommerce with Stripe integration.

## Recommendation

Prioritize the upgrade of the @payloadcms/plugin-ecommerce package to version 3.90.0 or higher, or 4.0.0-canary.34 or higher, to resolve CVE-2026-105850. In environments where immediate patching is not feasible, implement idempotency checks at the application or database layer to ensure Stripe webhooks related to order confirmation are only processed once per unique transaction identifier.
