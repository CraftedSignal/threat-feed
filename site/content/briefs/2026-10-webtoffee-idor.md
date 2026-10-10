---
title: Unauthenticated IDOR Vulnerability in WebToffee WooCommerce Plugin
slug: 2026-10-webtoffee-idor
description: An unauthenticated IDOR vulnerability in the WebToffee WooCommerce PDF Invoices plugin allows attackers to retrieve sensitive customer order documents by supplying a known email address.
date: "2026-10-10T09:51:41Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:webtoffee:woocommerce_pdf_invoices_packing_slips_delivery_notes_shipping_labels:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - idor
  - wordpress
vendors:
  - WebToffee
products:
  - WooCommerce PDF Invoices, Packing Slips, Delivery Notes & Shipping Labels (<= 5.0.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: This makes it possible for unauthenticated attackers to retrieve any other customer's invoice, packing slip, delivery note, dispatch label or shipping label by knowing the target order ID and the associated billing email address.
    confidence_band: high
cves:
  - id: CVE-2026-93746
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93746
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade WebToffee WooCommerce plugin to version 5.0.3 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-93746 patch availability
  mitigation_plan:
    - priority: immediate
      action: Set wt_pklist_print_button_access_for to logged_in in plugin settings
      owner: IT Operations
      addresses: CVE-2026-93746
      evidence: Source documentation on plugin configuration requirements
---

The WebToffee WooCommerce PDF Invoices, Packing Slips, Delivery Notes & Shipping Labels plugin for WordPress (versions 5.0.2 and earlier) contains an Insecure Direct Object Reference (IDOR) vulnerability. The vulnerability resides in the `print_document_from_the_mail_link` handler, which is triggered when `print_window()` is called during the `init` hook. When a site is configured to permit guest access to printable documents, the plugin fails to validate requests against the secure `order_key`. Instead, it authorizes document retrieval based solely on the `email` parameter. If an attacker provides a base64-encoded email address that matches the billing email of an order, the server returns the requested document. This allows unauthenticated actors to access sensitive data, including customer names, billing and shipping addresses, phone numbers, purchased product lists, tax information, and order metadata.

## Impact

Successful exploitation allows unauthenticated attackers to exfiltrate private customer order information at scale, provided they possess a valid order ID and the associated billing email address. This results in the unauthorized disclosure of personally identifiable information (PII) and financial transaction details, potentially impacting a large customer base for any affected e-commerce store.

## Recommendation

- Upgrade the WebToffee WooCommerce PDF Invoices, Packing Slips, Delivery Notes & Shipping Labels plugin to version 5.0.3 or later immediately to patch CVE-2026-93746.
- Audit web server access logs for anomalous, high-volume requests to WordPress endpoints associated with document printing functionality (e.g., URLs containing `print_document_from_the_mail_link`).
- Configure the plugin settings to restrict document access to logged-in users only, setting `wt_pklist_print_button_access_for` to `logged_in` as a temporary mitigation until the patch is applied.
