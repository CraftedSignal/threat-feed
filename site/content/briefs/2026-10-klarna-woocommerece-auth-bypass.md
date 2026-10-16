---
title: Authorization Bypass in Klarna for WooCommerce Plugin
slug: 2026-10-klarna-woocommerece-auth-bypass
description: An authorization bypass vulnerability in the Klarna for WooCommerce plugin allows unauthenticated attackers to enumerate store orders and exfiltrate customer PII via the order-pay endpoint.
date: "2026-10-16T06:25:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:klarna:klarna_for_woocommerce:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - privacy
  - vulnerability
vendors:
  - Klarna
products:
  - Klarna for WooCommerce (<= 4.13.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: Because WooCommerce order IDs are sequential integers and no order_key or authenticated session is required, every order in the store can be trivially enumerated with sequential GET requests to the order-pay endpoint.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: This makes it possible for unauthenticated attackers to access any order's secret order_key and full billing and shipping PII... enabling full store-wide order enumeration.
    confidence_band: high
cves:
  - id: CVE-2026-110590
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110590
rules:
  - title: Detect CVE-2026-110590 Exploitation - Automated Order Enumeration
    description: Detects high-frequency GET requests to the WooCommerce order-pay endpoint, which is characteristic of enumeration attacks targeting CVE-2026-110590.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1592
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Klarna for WooCommerce plugin to a version patched for CVE-2026-110590.
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable up to 4.13.3; requires update.
  hunt_leads:
    - lead: Search logs for sequential access patterns to /checkout/order-pay/ path.
      technique_id: T1592
      data_needed:
        - Web server logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly mentions sequential integer ID enumeration.
  mitigation_plan:
    - priority: immediate
      action: Update plugin to version > 4.13.3
      owner: IT Operations
      addresses: CVE-2026-110590
      evidence: NVD vulnerability disclosure
---

The Klarna for WooCommerce plugin for WordPress, in versions up to and including 4.13.3, contains a critical authorization bypass vulnerability (CVE-2026-110590). The flaw stems from the plugin's failure to verify user authorization before returning order details. Unauthenticated attackers can exploit this by sending crafted GET requests to the WooCommerce order-pay endpoint. The server responds by emitting sensitive customer PII - including full names, email addresses, phone numbers, and physical billing/shipping addresses - directly into the HTML source code within the 'klarna_payments_params' JavaScript variable. Because WooCommerce utilizes sequential integer-based order IDs, an attacker can trivially enumerate every order in a vulnerable store without needing authentication or a valid 'order_key'. This vulnerability poses a significant risk for mass data harvesting and privacy breaches for any merchant utilizing this plugin.

## Attack Chain

1. Attacker identifies a WordPress site running the Klarna for WooCommerce plugin (version <= 4.13.3).
2. Attacker probes the '/checkout/order-pay/' endpoint to confirm accessibility.
3. Attacker uses an automated script to increment sequential order IDs (e.g., /checkout/order-pay/1001, /checkout/order-pay/1002).
4. The vulnerable plugin processes the request without validating if the current session belongs to the order owner.
5. The server returns a 200 OK response containing the order page HTML.
6. Attacker scrapes the 'klarna_payments_params' JavaScript variable from the response body.
7. Attacker extracts PII (names, addresses, email, phone) from the scraped JSON-formatted variable.
8. Attacker compiles the enumerated records for exfiltration.

## Impact

Successful exploitation allows an unauthenticated attacker to scrape the entire order history of a WooCommerce store. This results in the exposure of extensive customer PII, including names, contact information, and physical addresses. With the increasing reliance on e-commerce, such a mass-data leak impacts customer privacy, violates compliance requirements (such as GDPR or CCPA), and can lead to secondary phishing or fraud attacks against the affected customers.

## Recommendation

* Update the Klarna for WooCommerce plugin to the latest version (patch for CVE-2026-110590) immediately.
* Monitor web server logs for high-frequency GET requests to '/checkout/order-pay/' originating from single IP addresses.
* Review web application firewall (WAF) logs for unauthorized access to order-pay paths and set rate-limiting policies for these endpoints.
* Deploy the Sigma rule below to detect automated enumeration attempts against the checkout/order-pay infrastructure.
