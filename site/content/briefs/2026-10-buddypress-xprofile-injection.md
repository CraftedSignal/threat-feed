---
brief_id: brief-2026-10-29-buddypress-xprofile-injection
event_id: brief-2026-10-29-buddypress-xprofile-injection
revision: 1
activity_at: "2026-10-29T18:43:18Z"
title: BuddyPress Xprofile Custom Field Types PHP Object Injection (CVE-2026-116868)
slug: 2026-10-buddypress-xprofile-injection
description: The BuddyPress Xprofile Custom Field Types plugin (versions <= 1.3.1) contains a Subscriber PHP Object Injection vulnerability.
date: "2026-10-29T18:43:18Z"
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
  - cpe:2.3:a:buddypress:xprofile_custom_field_types:*:*:*:*:*:*:*:*
vendors:
  - BuddyPress
products:
  - Xprofile Custom Field Types (<= 1.3.1)
cves:
  - id: CVE-2026-116868
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116868
---

The BuddyPress Xprofile Custom Field Types plugin, in versions 1.3.1 and earlier, is vulnerable to a Subscriber PHP Object Injection.
