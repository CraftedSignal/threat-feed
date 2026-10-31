---
brief_id: brief-2026-10-31-wp-booking-plugin-auth-bypass
event_id: brief-2026-10-31-wp-booking-plugin-auth-bypass
revision: 1
activity_at: "2026-10-31T07:51:01Z"
title: WP Booking System - Booking Calendar unauthorized data modification (CVE-2026-116557)
slug: 2026-10-wp-booking-plugin-auth-bypass
description: The WP Booking System - Booking Calendar plugin contains a vulnerability in the wpbs_action_ajax_calendar_remove_note function that allows authenticated users to delete arbitrary calendar notes due to a missing capability check.
date: "2026-10-31T07:51:01Z"
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
  - WP Booking System - Booking Calendar (<= 2.1.0.5)
cves:
  - id: CVE-2026-116557
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116557
---

The WP Booking System - Booking Calendar plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the wpbs_action_ajax_calendar_remove_note() function in versions up to, and including, 2.1.0.5. This allows authenticated attackers with Subscriber-level access or higher to delete arbitrary calendar notes.
