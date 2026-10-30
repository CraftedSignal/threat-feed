---
brief_id: brief-2026-10-30-email-templates-customizer-auth-bypass
event_id: brief-2026-10-30-email-templates-customizer-auth-bypass
revision: 1
activity_at: "2026-10-30T19:36:24Z"
title: 'Email Templates Customizer and Designer for WordPress and WooCommerce: Authorization bypass (CVE-2026-107630)'
slug: 2026-10-email-templates-customizer-auth-bypass
description: The Email Templates Customizer and Designer for WordPress and WooCommerce plugin is vulnerable to an authorization bypass allowing unauthenticated attackers to enumerate WooCommerce order IDs and exfiltrate customer PII.
date: "2026-10-30T19:36:24Z"
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
products:
  - Email Templates Customizer and Designer for WordPress and WooCommerce (up to and including 1.5.14)
cves:
  - id: CVE-2026-107630
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107630
---

The Email Templates Customizer and Designer for WordPress and WooCommerce plugin (all versions up to, and including, 1.5.14) is vulnerable to an authorization bypass. The plugin fails to properly verify user authorization, allowing unauthenticated attackers to enumerate WooCommerce order IDs via the `preview_order` parameter and exfiltrate customer billing names, addresses, phone numbers, and email addresses. Exploitation involves harvesting a reusable nonce from the 302 Location header of an unguarded `admin_init` handler and using it to access the preview endpoint.
