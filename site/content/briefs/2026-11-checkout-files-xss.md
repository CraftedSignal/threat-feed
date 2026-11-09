---
brief_id: brief-2026-11-09-checkout-files-xss
event_id: brief-2026-11-09-checkout-files-xss
revision: 1
activity_at: "2026-11-09T11:39:57Z"
title: 'WP Wham Checkout Files Upload for WooCommerce: Stored Cross-Site Scripting (CVE-2026-123463)'
slug: 2026-11-checkout-files-xss
description: The Checkout Files Upload for WooCommerce plugin (versions up to and including 2.4.0) contains an improper neutralization of input vulnerability, resulting in Stored Cross-Site Scripting (XSS).
date: "2026-11-09T11:39:57Z"
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
  - cpe:2.3:a:wp_wham:checkout_files_upload_for_woocommerce:*:*:*:*:*:*:*:*
vendors:
  - WP Wham
products:
  - Checkout Files Upload for WooCommerce (n/a through 2.4.0)
cves:
  - id: CVE-2026-123463
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123463
---

The Checkout Files Upload for WooCommerce plugin (checkout-files-upload-woocommerce), in versions from n/a through 2.4.0, is affected by an Improper Neutralization of Input During Web Page Generation vulnerability, identified as Stored Cross-site Scripting (XSS).
