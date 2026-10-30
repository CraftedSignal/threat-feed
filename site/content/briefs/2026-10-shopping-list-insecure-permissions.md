---
brief_id: brief-2026-10-30-shopping-list-insecure-permissions
event_id: brief-2026-10-30-shopping-list-insecure-permissions
revision: 1
activity_at: "2026-10-30T19:37:14Z"
title: 'wbpxre150 Shopping List: Insecure component permissions (CVE-2026-107028)'
slug: 2026-10-shopping-list-insecure-permissions
description: Insecure permissions in wbpxre150 Shopping List v11.0 (versionCode 11) allow unauthorized attackers to invoke an exported component, leading to manipulation of the shopping-list data.
date: "2026-10-30T19:37:14Z"
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
  - cpe:2.3:a:wbpxre150:shopping_list:*:*:*:*:*:*:*:*
vendors:
  - wbpxre150
products:
  - Shopping List (11.0)
cves:
  - id: CVE-2026-107028
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107028
---

The Android application Shopping List version 11.0 (versionCode 11) contains a vulnerability where insecure permissions allow unauthorized attackers to invoke an exported component. This results in the potential manipulation of shopping-list data.
