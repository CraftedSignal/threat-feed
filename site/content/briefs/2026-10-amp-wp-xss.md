---
brief_id: brief-2026-10-28-amp-wp-xss
event_id: brief-2026-10-28-amp-wp-xss
revision: 1
activity_at: "2026-10-28T08:26:46Z"
title: 'AMP for WP - Accelerated Mobile Pages: Stored Cross-Site Scripting (CVE-2026-97019)'
slug: 2026-10-amp-wp-xss
description: The AMP for WP - Accelerated Mobile Pages plugin for WordPress is vulnerable to Stored Cross-Site Scripting via 'headline-*' shortcode attributes due to insufficient input sanitization and output escaping.
date: "2026-10-28T08:26:46Z"
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
  - AMP for WP – Accelerated Mobile Pages (<= 1.1.17)
cves:
  - id: CVE-2026-97019
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97019
---

The AMP for WP - Accelerated Mobile Pages plugin for WordPress, in all versions up to and including 1.1.17, contains a Stored Cross-Site Scripting vulnerability. The issue arises from insufficient input sanitization and output escaping within 'headline-*' shortcode attributes. A Subscriber-level user can store a malicious shortcode in their biographical info field, which executes when a user accesses the injected page. Unauthenticated attackers may also inject arbitrary web scripts into pages.
