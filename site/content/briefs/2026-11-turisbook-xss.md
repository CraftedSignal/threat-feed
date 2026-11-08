---
brief_id: brief-2026-11-08-turisbook-xss
event_id: brief-2026-11-08-turisbook-xss
revision: 1
activity_at: "2026-11-08T21:27:50Z"
title: 'Turisbook Booking System: Stored Cross-Site Scripting (CVE-2026-103303)'
slug: 2026-11-turisbook-xss
description: The Turisbook Booking System WordPress plugin through 1.3.8 lacks authorization and CSRF protections and fails to sanitize output, allowing unauthenticated users to perform Stored Cross-Site Scripting attacks against administrators.
date: "2026-11-08T21:27:50Z"
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
  - cpe:2.3:a:turisbook:booking_system:*:*:*:*:*:*:*:*
vendors:
  - Turisbook
products:
  - Turisbook Booking System (<= 1.3.8)
cves:
  - id: CVE-2026-103303
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103303
---

The Turisbook Booking System WordPress plugin, in versions through 1.3.8, does not have authorization and CSRF checks when saving settings. Additionally, the plugin does not sanitize or escape a setting before outputting it in an admin page, allowing unauthenticated users to perform Stored Cross-Site Scripting attacks against administrators.
