---
brief_id: brief-2026-11-05-litespeed-cache-disclosure
event_id: brief-2026-11-05-litespeed-cache-disclosure
revision: 1
activity_at: "2026-11-05T06:28:37Z"
title: 'LiteSpeed Cache: Unauthenticated WooCommerce data disclosure (CVE-2026-93389)'
slug: 2026-11-litespeed-cache-disclosure
description: The LiteSpeed Cache plugin for WordPress up to version 7.9.1 contains an information disclosure vulnerability that allows unauthenticated attackers to access sensitive WooCommerce customer data and session tokens via improper public caching of REST API responses.
date: "2026-11-05T06:28:37Z"
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
  - cpe:2.3:a:litespeedtech:litespeed_cache:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - wordpress
  - information-disclosure
  - cve-2026-93389
vendors:
  - LiteSpeed
products:
  - LiteSpeed Cache (<= 7.9.1)
cves:
  - id: CVE-2026-93389
    cvss: 8.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93389
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Disable "Cache REST" feature in LiteSpeed Cache settings
      owner: IT Operations
      due: 24h
      evidence: The vulnerability occurs when Cache REST is enabled (default) as it forces the storage of Store API responses as public cache objects.
  hunt_leads:
    - lead: Identify unauthenticated access to WooCommerce Store API endpoints resulting in potential sensitive data exposure
      technique_id: T1552.001
      data_needed:
        - Web server logs containing requested URI, HTTP status, and user-agent
        - Application-level access logs for WooCommerce endpoints
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can read shopper billing details and session JWTs by requesting /wc/store/v1/cart and /wc/store/v1/checkout.
  mitigation_plan:
    - priority: immediate
      action: Upgrade LiteSpeed Cache to a version patched against CVE-2026-93389
      owner: IT Operations
      addresses: CVE-2026-93389
      evidence: Vulnerable in all versions up to, and including, 7.9.1.
---

The LiteSpeed Cache plugin for WordPress (versions 7.9.1 and earlier) is vulnerable to unauthenticated information disclosure. When the "Cache REST" feature is enabled - which is the default configuration - the plugin stores WooCommerce Store API responses for `/wc/store/v1/cart` and `/wc/store/v1/checkout` as public cache objects. The plugin fails to apply proper cache variation based on WooCommerce session cookies or Cart-Token headers. Consequently, a personalized response belonging to an authenticated shopper can be served to any subsequent, unauthenticated visitor. Attackers can leverage this to harvest PII (names, addresses, emails, phone numbers) and extract Cart-Token session JWTs and nonces, facilitating session hijacking.

## Impact

Successful exploitation allows unauthenticated attackers to gain unauthorized access to sensitive customer billing and shipping information, view cart contents, and perform session hijacking by stealing Cart-Token session JWTs and nonces.

## Recommendation

* Upgrade the LiteSpeed Cache plugin to a patched version beyond 7.9.1 immediately.
* If patching is not immediately feasible, disable the "Cache REST" feature within the LiteSpeed Cache plugin settings to prevent sensitive Store API responses from being stored in the public cache.
* Audit web server access logs for anomalous, high-frequency GET requests to `/wc/store/v1/cart` and `/wc/store/v1/checkout` endpoints originating from unrecognized IP addresses or missing expected session headers.
