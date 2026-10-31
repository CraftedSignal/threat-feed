---
brief_id: brief-2026-10-31-shield-security-xss
event_id: brief-2026-10-31-shield-security-xss
revision: 1
activity_at: "2026-10-31T11:57:24Z"
title: 'Shield Security WordPress Plugin: Stored Cross-Site Scripting (CVE-2026-118057)'
slug: 2026-10-shield-security-xss
description: The Shield Security - Smart Bot Blocking, Brute-Force Login Protection & File Scanning plugin for WordPress contains a Stored Cross-Site Scripting vulnerability via the 'REQUEST_URI' parameter in versions up to and including 22.3.2.
date: "2026-10-31T11:57:24Z"
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
  - cpe:2.3:a:shield_security:smart_bot_blocking_brute_force_login_protection_file_scanning:*:*:*:*:*:*:*:*
vendors:
  - Shield Security
products:
  - Shield Security – Smart Bot Blocking, Brute-Force Login Protection & File Scanning (<= 22.3.2)
cves:
  - id: CVE-2026-118057
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118057
---

The Shield Security - Smart Bot Blocking, Brute-Force Login Protection & File Scanning plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'REQUEST_URI' parameter in all versions up to, and including, 22.3.2. This is due to insufficient input sanitization and output escaping. 

The hidden 'path' column in ForTraffic.php lacks a client-side render function, causing DataTables to build its cell via innerHTML. This results in stored HTML in the path value being parsed into live DOM nodes. A prior partial fix in version 18.5.8 added esc_html() to the visible 'page' column, but left the hidden 'path' field unescaped and exploitable through version 22.2.6. This vulnerability allows unauthenticated attackers to inject arbitrary web scripts that execute when a user accesses an injected page.
