---
brief_id: brief-2026-10-31-woocommerce-xss
event_id: brief-2026-10-31-woocommerce-xss
revision: 1
activity_at: "2026-10-31T07:51:55Z"
title: 'PDF Invoices & Packing Slips for WooCommerce: Stored XSS via billing address fields (CVE-2026-107750)'
slug: 2026-10-woocommerce-xss
description: The PDF Invoices & Packing Slips for WooCommerce plugin for WordPress is vulnerable to Stored Cross-Site Scripting due to insufficient input sanitization and output escaping.
date: "2026-10-31T07:51:55Z"
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
  - cpe:2.3:a:wordpress:pdf_invoices_packing_slips_for_woocommerce:*:*:*:*:*:*:*:*
vendors:
  - WordPress
products:
  - PDF Invoices & Packing Slips for WooCommerce (versions up to and including 5.16.4)
cves:
  - id: CVE-2026-107750
    cvss: 7.2
    kev_status: "false"
  - id: CVE-2026-92244
    cvss: 7.2
    epss: 0.00284
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107750
---

The PDF Invoices & Packing Slips for WooCommerce plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) in versions up to and including 5.16.4. The vulnerability affects the 'billing_address.first_name', 'last_name', 'company', and 'customer_note' parameters. 

The issue arises from an incomplete fix for CVE-2026-92244; while the 'wp_kses()' function blocks raw-tag payloads, it is bypassed by entity-encoded payloads that contain no literal angle-bracket characters. This allows unauthenticated attackers to inject arbitrary web scripts that execute when a user accesses an injected page.
