---
title: IDOR Vulnerability in FluentCart WordPress Plugin
slug: 2026-10-fluentcart-idor
description: The FluentCart plugin for WordPress up to version 1.7.0 contains an IDOR vulnerability allowing unauthenticated attackers to exfiltrate customer billing and shipping PII via sequential ID enumeration.
date: "2026-10-16T06:25:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:fluentcart:fluentcart:*:*:*:*:*:wordpress:*:*
vendors:
  - FluentCart
products:
  - FluentCart A New Era of eCommerce – Faster, Lighter, and Simpler (<= 1.7.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The FluentCart plugin for WordPress up to version 1.7.0 is vulnerable to Insecure Direct Object Reference via the 'order_id + billing_address_id' parameter due to missing validation on a user controlled key.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: This makes it possible for unauthenticated attackers to read and exfiltrate another customer's stored billing and shipping address PII by enumerating sequential AUTO_INCREMENT order and address ID pairs.
    confidence_band: high
cves:
  - id: CVE-2026-103525
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103525
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update FluentCart plugin to version 1.7.1 or higher
      owner: IT Operations
      due: 24h
      evidence: Source states all versions up to 1.7.0 are vulnerable
  hunt_leads:
    - lead: Search web logs for sequential incrementing of order_id or address_id parameters
      technique_id: T1083
      data_needed:
        - web_server_access_logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attacker exfiltrates data by enumerating sequential AUTO_INCREMENT order and address ID pairs
  mitigation_plan:
    - priority: immediate
      action: Upgrade FluentCart to the latest version to patch CVE-2026-103525
      owner: IT Operations
      addresses: CVE-2026-103525
      evidence: Plugin vulnerable in all versions up to 1.7.0
---

The FluentCart WordPress plugin (version 1.7.0 and earlier) contains an Insecure Direct Object Reference (IDOR) vulnerability identified as CVE-2026-103525. The flaw resides in an unauthenticated AJAX entry point designed for order and address retrieval. Because the plugin lacks server-side authorization checks, it relies entirely on client-provided order_id and address_id parameters. An attacker can enumerate these identifiers by exploiting the sequential nature of AUTO_INCREMENT database keys. By cycling through these numerical values, an unauthenticated user can exfiltrate sensitive customer PII, including street addresses, phone numbers, company names, VAT numbers, and legal registration IDs. Although a soft rate limit of five requests per 60 seconds exists, it is insufficient to prevent automated enumeration of the database over time. This vulnerability poses a significant risk to customer privacy and regulatory compliance.

## Impact

Successful exploitation results in the unauthorized mass exfiltration of sensitive customer PII. Victims include any WordPress e-commerce site utilizing the vulnerable FluentCart plugin versions. Exposed data encompasses physical addresses, contact information, and business-related tax documentation, potentially leading to identity theft, fraud, or violations of data protection regulations.

## Recommendation

* Update the FluentCart plugin to the latest available version beyond 1.7.0 immediately.
* Implement web application firewall (WAF) rules to detect and block high-frequency sequential requests to the specific AJAX endpoints associated with this plugin.
* Review web server access logs for anomalous, high-frequency POST or GET requests to the plugin's address/order retrieval AJAX URI patterns that result in HTTP 200 status codes but originate from distinct, unauthenticated sessions.
* Monitor for enumeration patterns in traffic, specifically looking for increments in numerical URL parameters or query strings associated with order retrieval.
