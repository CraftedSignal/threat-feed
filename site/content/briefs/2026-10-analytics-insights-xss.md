---
brief_id: brief-2026-10-27-analytics-insights-xss
event_id: brief-2026-10-27-analytics-insights-xss
revision: 1
activity_at: "2026-10-27T07:48:52Z"
title: 'Analytics Insights Google Analytics Dashboard: Stored Cross-Site Scripting (CVE-2026-111820)'
slug: 2026-10-analytics-insights-xss
description: The Analytics Insights - Google Analytics Dashboard for WordPress plugin is vulnerable to Stored Cross-Site Scripting via the Page Title in all versions up to, and including, 6.3.12 due to insufficient input sanitization and output escaping.
date: "2026-10-27T07:48:52Z"
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
  - Analytics Insights – Google Analytics Dashboard for WordPress (<= 6.3.12)
cves:
  - id: CVE-2026-111820
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111820
---

The Analytics Insights - Google Analytics Dashboard for WordPress plugin is vulnerable to Stored Cross-Site Scripting via the Page Title in all versions up to, and including, 6.3.12 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
