---
brief_id: brief-2026-11-07-latepoint-auth-bypass
event_id: brief-2026-11-07-latepoint-auth-bypass
revision: 2
activity_at: "2026-11-09T19:36:40Z"
revision_history:
  - revision: 2
    at: "2026-11-09T19:36:40Z"
    checksum: sha256:4d5b0fbd267dce6d60217998e4cfb423c58fa9f60c47e0630cc79c68cdbcd861
    summary: poc_available
    changed_fields:
      - claim_state
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KS:SCANNER-HTTP-LATEPOINT_CVE_2026_118066_DETECT&utm_source=rss&utm_medium=rss
title: 'LatePoint Appointment Booking: Authentication bypass and account takeover (CVE-2026-118066)'
slug: 2026-11-latepoint-auth-bypass
description: The LatePoint Appointment Booking plugin for WordPress is vulnerable to authentication bypass and account takeover due to improper SQL query construction.
date: "2026-11-07T14:44:07Z"
lastmod: "2026-11-09T19:36:05Z"
type: advisory
claim_state: <nil>
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
  - cpe:2.3:a:latepoint:appointment_booking_plugin_latepoint_calendar_scheduling_for_wordpress:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KS:SCANNER-HTTP-LATEPOINT_CVE_2026_118066_DETECT&utm_source=rss&utm_medium=rss
vendors:
  - LatePoint
products:
  - Appointment Booking Plugin – LatePoint | Calendar & Scheduling for WordPress (<= 5.7.6)
cves:
  - id: CVE-2026-118066
    cvss: 9.1
    epss: 0.00851
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118066
  - https://sploitus.com/exploit?id=KS:SCANNER-HTTP-LATEPOINT_CVE_2026_118066_DETECT&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-09T19:36:05Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KS:SCANNER-HTTP-LATEPOINT_CVE_2026_118066_DETECT&utm_source=rss&utm_medium=rss
---

The Appointment Booking Plugin - LatePoint | Calendar & Scheduling for WordPress is vulnerable to Authentication Bypass via Account Takeover in all versions up to, and including, 5.7.6. The flaw exists in `OsModel::build_conditions_query()` in `lib/models/model.php`, where SQL WHERE-clause values are concatenated without proper parameter binding. An unauthenticated attacker can exploit this by sending `IS NOT NULL` to public AJAX routes to enumerate customer PII via `steps__start_from_order_intent` or overwrite passwords via `customer_cabinet__change_password`. If the `wp_users_as_customers` option is enabled, this allows takeover of linked WordPress subscriber or customer-role accounts.
