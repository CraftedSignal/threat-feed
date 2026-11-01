---
brief_id: brief-2026-11-01-wordpress-file-upload-xss
event_id: brief-2026-11-01-wordpress-file-upload-xss
revision: 1
activity_at: "2026-11-01T16:57:24Z"
title: 'Nickboss WordPress File Upload: Stored Cross-Site Scripting (CVE-2026-66570)'
slug: 2026-11-wordpress-file-upload-xss
description: The Nickboss WordPress File Upload plugin (up to version 5.2.1) is vulnerable to Stored Cross-Site Scripting (XSS) due to improper neutralization of input during web page generation.
date: "2026-11-01T16:57:24Z"
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
  - cpe:2.3:a:nickboss:wordpress_file_upload:*:*:*:*:*:*:*:*
vendors:
  - Nickboss
products:
  - WordPress File Upload (n/a through 5.2.1)
cves:
  - id: CVE-2026-66570
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66570
---

The WordPress File Upload plugin (wp-file-upload) by Nickboss is affected by a Stored Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-66570. This issue is caused by the improper neutralization of input during web page generation and affects the plugin from version n/a through 5.2.1.
