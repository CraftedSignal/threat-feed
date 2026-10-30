---
brief_id: brief-2026-10-30-gravity-forms-xss-d96f0cfe
event_id: brief-2026-10-30-gravity-forms-xss-d96f0cfe
revision: 1
activity_at: "2026-10-30T09:27:24Z"
title: 'Gravity Forms: Stored Cross-Site Scripting (CVE-2026-97645)'
slug: 2026-10-gravity-forms-xss-d96f0cfe
description: The Gravity Forms plugin for WordPress (all versions up to, and including, 3.1.2) is vulnerable to Stored Cross-Site Scripting (XSS) via the List Field due to insufficient input sanitization and output escaping.
date: "2026-10-30T09:27:24Z"
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
  - cpe:2.3:a:gravity_forms:gravity_forms:*:*:*:*:*:*:*:*
vendors:
  - Gravity Forms
products:
  - Gravity Forms (<= 3.1.2)
cves:
  - id: CVE-2026-97645
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97645
---

The Gravity Forms plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the List Field in all versions up to, and including, 3.1.2. This vulnerability stems from insufficient input sanitization and output escaping, allowing unauthenticated attackers to inject arbitrary web scripts. The injected scripts execute when an administrator accesses an injected page, clicks the injected link in the entry detail view, and confirms a dialog. This action triggers the admin JavaScript bundle's delegated data-dialog-callback handler to invoke the attacker-supplied function reference.
