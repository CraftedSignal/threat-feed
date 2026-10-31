---
brief_id: brief-2026-10-31-thirstyaffiliates-xss
event_id: brief-2026-10-31-thirstyaffiliates-xss
revision: 1
activity_at: "2026-10-31T09:54:56Z"
title: 'ThirstyAffiliates Plugin: Stored Cross-Site Scripting (CVE-2026-119089)'
slug: 2026-10-thirstyaffiliates-xss
description: The ThirstyAffiliates plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'comment' parameter due to insufficient input sanitization and output escaping.
date: "2026-10-31T09:54:56Z"
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
  - ThirstyAffiliates – Affiliate Links, Link Branding, Link Tracking & Marketing Plugin (<= 3.12.1)
cves:
  - id: CVE-2026-119089
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119089
---

The ThirstyAffiliates - Affiliate Links, Link Branding, Link Tracking & Marketing Plugin for WordPress (all versions up to and including 3.12.1) contains a Stored Cross-Site Scripting vulnerability in the 'comment' parameter. The vulnerability allows unauthenticated attackers to inject arbitrary web scripts that execute when a user accesses an injected page. Exploitation is limited to block themes where the Comment Content block triggers the plugin's transformer, and requires one previously approved comment to facilitate the auto-approval of subsequent malicious comments.
