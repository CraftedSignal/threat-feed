---
brief_id: brief-2026-10-24-knit-pay-auth-bypass
event_id: brief-2026-10-24-knit-pay-auth-bypass
revision: 1
activity_at: "2026-10-24T18:18:29Z"
title: 'Knit Pay UPI QR Code Payment Gateway: Missing Authorization Vulnerability (CVE-2026-114191)'
slug: 2026-10-knit-pay-auth-bypass
description: A missing authorization vulnerability exists in the Knit Pay UPI QR Code Payment Gateway for WooCommerce plugin, affecting versions from n/a through 1.6.3. The vulnerability allows for the exploitation of incorrectly configured access control security levels.
date: "2026-10-24T18:18:29Z"
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
  - cpe:2.3:a:knit_pay:upi_qr_code_payment_gateway_for_woocommerce:*:*:*:*:*:*:*:*
vendors:
  - Knit Pay
products:
  - UPI QR Code Payment Gateway for WooCommerce (n/a through 1.6.3)
cves:
  - id: CVE-2026-114191
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114191
---
