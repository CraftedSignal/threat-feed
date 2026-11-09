---
brief_id: brief-2026-11-09-rsvp-xss
event_id: brief-2026-11-09-rsvp-xss
revision: 1
activity_at: "2026-11-09T11:40:32Z"
title: 'WP Chill RSVP and Event Management: Stored Cross-Site Scripting (CVE-2026-121570)'
slug: 2026-11-rsvp-xss
description: A stored cross-site scripting (XSS) vulnerability exists in the WP Chill RSVP and Event Management plugin due to improper neutralization of input during web page generation.
date: "2026-11-09T11:40:32Z"
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
  - cpe:2.3:a:wp_chill:rsvp_and_event_management:*:*:*:*:*:*:*:*
vendors:
  - WP Chill
products:
  - RSVP and Event Management (n/a through 2.7.17)
cves:
  - id: CVE-2026-121570
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121570
---

The RSVP and Event Management plugin for WordPress (versions from n/a through 2.7.17) is affected by an Improper Neutralization of Input During Web Page Generation vulnerability, classified as Stored XSS.
