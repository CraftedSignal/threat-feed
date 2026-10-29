---
brief_id: brief-2026-10-29-wp-swings-xss
event_id: brief-2026-10-29-wp-swings-xss
revision: 1
activity_at: "2026-10-29T13:21:09Z"
title: 'WP Swings Upsell Order Bump Offer for WooCommerce: Reflected Cross-site Scripting (CVE-2026-116409)'
slug: 2026-10-wp-swings-xss
description: A reflected cross-site scripting vulnerability in WP Swings Upsell Order Bump Offer for WooCommerce (versions <= 3.1.6) allows attackers to execute arbitrary scripts in a user's browser via crafted input.
date: "2026-10-29T13:21:09Z"
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
  validation_status: Source validated, detection logic limited to network monitoring due to lack of specific URL parameters in source.
cpes:
  - cpe:2.3:a:wpswings:upsell_order_bump_offer_for_woocommerce:*:*:*:*:*:wordpress:*:*
tags:
  - xss
  - web-application
  - wordpress
  - vulnerability
vendors:
  - WP Swings
products:
  - Upsell Order Bump Offer for WooCommerce (n/a <= 3.1.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: This allows an attacker to execute arbitrary scripts in the victim's browser if they can trick a user into clicking a malicious link.
    confidence_band: high
cves:
  - id: CVE-2026-116409
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116409
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all WordPress sites running the affected plugin
      owner: IT Operations
      due: 24h
      evidence: Plugin identified in NVD advisory
  hunt_leads:
    - lead: Search web server access logs for anomalous GET requests targeting WooCommerce plugin paths with script-like characters in query parameters
      technique_id: T1189
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Reflected XSS vulnerability in WordPress plugin
  mitigation_plan:
    - priority: immediate
      action: Upgrade Upsell Order Bump Offer for WooCommerce to a patched version beyond 3.1.6
      owner: IT Operations
      addresses: CVE-2026-116409
      evidence: Vulnerability affects versions through 3.1.6
---

CVE-2026-116409 is a reflected cross-site scripting (XSS) vulnerability affecting the WP Swings Upsell Order Bump Offer for WooCommerce plugin. The flaw originates from improper neutralization of user-supplied input during web page generation. An attacker can exploit this by crafting a malicious URL that, when visited by a victim (such as an administrator), executes arbitrary JavaScript in the context of their session. This version range covers all installations from n/a through 3.1.6.

## Impact

Successful exploitation allows for arbitrary script execution within the victim's browser session. Depending on the victim's privileges, this may lead to session hijacking, unauthorized actions on the WooCommerce store, or further site compromise.

## Recommendation

* Inventory all WordPress instances running the 'Upsell Order Bump Offer for WooCommerce' plugin.
* Update the plugin to a version beyond 3.1.6 immediately upon the vendor's release of a patch.
* Implement a Content Security Policy (CSP) to mitigate the impact of potential XSS attacks.
* Monitor WordPress web server access logs for requests containing suspicious script-like patterns or excessive parameters in URI queries.
