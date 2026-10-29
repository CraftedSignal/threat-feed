---
brief_id: brief-2026-10-29-wordpress-import-plugin-lfi
event_id: brief-2026-10-29-wordpress-import-plugin-lfi
revision: 1
activity_at: "2026-10-29T13:19:09Z"
title: 'Automated Import Products to Cart: Arbitrary file read and deletion (CVE-2026-113617)'
slug: 2026-10-wordpress-import-plugin-lfi
description: The Automated Import Products to Cart WordPress plugin before 1.0.4 does not sanitize user-supplied file paths, allowing users with minimal permissions to read or delete arbitrary files on the server.
date: "2026-10-29T13:19:09Z"
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
products:
  - Automated Import Products to Cart (< 1.0.4)
cves:
  - id: CVE-2026-113617
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113617
---
