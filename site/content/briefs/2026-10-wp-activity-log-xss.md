---
brief_id: brief-2026-10-31-wp-activity-log-xss
event_id: brief-2026-10-31-wp-activity-log-xss
revision: 1
activity_at: "2026-10-31T09:56:16Z"
title: 'WP Activity Log: Stored Cross-Site Scripting (CVE-2026-120075)'
slug: 2026-10-wp-activity-log-xss
description: The WP Activity Log plugin for WordPress is vulnerable to Stored Cross-Site Scripting in all versions up to and including 5.6.1 due to insufficient input sanitization and output escaping, allowing unauthenticated attackers to inject arbitrary web scripts.
date: "2026-10-31T09:56:16Z"
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
  - cpe:2.3:a:wp_activity_log:wp_activity_log:*:*:*:*:*:*:*:*
vendors:
  - WP Activity Log
products:
  - WP Activity Log (<= 5.6.1)
cves:
  - id: CVE-2026-120075
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120075
---

The WP Activity Log plugin for WordPress, in all versions up to and including 5.6.1, is vulnerable to Stored Cross-Site Scripting. This vulnerability is caused by insufficient input sanitization and output escaping. Unauthenticated attackers can inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
