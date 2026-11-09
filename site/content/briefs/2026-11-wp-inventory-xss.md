---
brief_id: brief-2026-11-09-wp-inventory-xss
event_id: brief-2026-11-09-wp-inventory-xss
revision: 1
activity_at: "2026-11-09T11:38:57Z"
title: 'WP Inventory Manager: Reflected Cross-site Scripting (CVE-2026-111403)'
slug: 2026-11-wp-inventory-xss
description: WP Inventory Manager (from n/a through 2.5.9) is affected by a Reflected Cross-site Scripting vulnerability due to improper neutralization of input during web page generation.
date: "2026-11-09T11:38:57Z"
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
  - cpe:2.3:a:wp-inventory:wp_inventory_manager:*:*:*:*:*:wordpress:*:*
vendors:
  - WP Inventory Manager
products:
  - WP Inventory Manager (n/a through 2.5.9)
cves:
  - id: CVE-2026-111403
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111403
---

A vulnerability categorized as Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') exists in the WP Inventory Manager plugin for WordPress. This issue affects versions from n/a through 2.5.9 and allows for Reflected XSS.
