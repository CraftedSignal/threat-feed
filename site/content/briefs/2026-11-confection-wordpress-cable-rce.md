---
brief_id: brief-2026-11-09-confection-wordpress-cable-rce
event_id: brief-2026-11-09-confection-wordpress-cable-rce
revision: 1
activity_at: "2026-11-09T11:40:25Z"
title: 'Confection WordPress Cable: Unauthenticated Remote Code Execution (CVE-2026-115252)'
slug: 2026-11-confection-wordpress-cable-rce
description: The Confection WordPress Cable plugin (versions 0.4.0 to 0.4.7) is vulnerable to unauthenticated remote code execution due to a lack of capability and nonce checks.
date: "2026-11-09T11:40:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:confection:wordpress_cable:*:*:*:*:*:*:*:*
vendors:
  - Confection
products:
  - WordPress Cable (0.4.0 - 0.4.7)
cves:
  - id: CVE-2026-115252
    cvss: 10
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115252
---

The Confection WordPress Cable WordPress plugin (versions 0.4.0 to 0.4.7) does not perform capability or nonce checks before saving its settings. The plugin writes settings, unmodified, into a standalone PHP file that it then serves, allowing unauthenticated users to execute arbitrary PHP code on the server.
