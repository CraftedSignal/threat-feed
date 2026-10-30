---
brief_id: brief-2026-10-30-food-store-xss-0425c09a
event_id: brief-2026-10-30-food-store-xss-0425c09a
revision: 1
activity_at: "2026-10-30T09:26:57Z"
title: 'The Food Store WordPress plugin: Stored Cross-Site Scripting (CVE-2026-116622)'
slug: 2026-10-food-store-xss-0425c09a
description: The Food Store WordPress plugin is vulnerable to unauthenticated Stored Cross-Site Scripting via the service_time parameter in versions up to 1.5.5, allowing attackers to inject malicious scripts into administrative or user-facing pages.
date: "2026-10-30T09:26:57Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified; environment validation required to confirm plugin configuration risk
cpes:
  - cpe:2.3:a:the_food_store_project:the_food_store:*:*:*:*:*:wordpress:*:*
vendors:
  - WordPress
products:
  - The Food Store – Online Food Delivery & Pickup (<= 1.5.5)
cves:
  - id: CVE-2026-116622
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116622
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade The Food Store plugin to the latest version to patch CVE-2026-116622
      owner: IT Operations
      due: 48h
      evidence: The Food Store - Online Food Delivery & Pickup plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the service_time parameter in all versions up to, and including, 1.5.5
  hunt_leads:
    - lead: Search web server access logs for POST requests containing script tags or JavaScript event handlers in the request body for the service_time parameter.
      technique_id: T1059.007
      data_needed:
        - Web server access logs (e.g., Apache/Nginx access.log)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Unauthenticated attackers can inject arbitrary web scripts
  mitigation_plan:
    - priority: immediate
      action: Disable Enable Pickup/Delivery Service in plugin configuration
      owner: IT Operations
      addresses: CVE-2026-116622
      evidence: Exploitation requires the site to have the Enable Checkout Service Fields option turned off, which is a non-default configuration, while Enable Pickup/Delivery Service remains enabled.
---

The Food Store - Online Food Delivery & Pickup plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) via the 'service_time' parameter. The vulnerability stems from insufficient input sanitization and output escaping. An unauthenticated attacker can exploit this to inject arbitrary JavaScript that executes in the context of a user's browser session.

The vulnerability is exploitable only under a specific non-default configuration: the 'Enable Checkout Service Fields' option must be disabled, while the 'Enable Pickup/Delivery Service' option must be enabled.

## Impact

Successful exploitation allows for the execution of arbitrary web scripts in the browser of a victim, such as an administrator, which could lead to session hijacking, unauthorized actions performed on behalf of the user, or redirection to malicious content.

## Recommendation

- Upgrade "The Food Store - Online Food Delivery & Pickup" plugin to the latest version beyond 1.5.5 immediately.
- If an update is unavailable, temporarily disable the 'Enable Pickup/Delivery Service' setting until a patch is applied.
- Review WordPress audit logs for unusual POST requests targeting 'service_time' parameters.
