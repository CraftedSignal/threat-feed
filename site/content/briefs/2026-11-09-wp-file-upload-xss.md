---
brief_id: brief-2026-11-09-wp-file-upload-xss
event_id: brief-2026-11-09-wp-file-upload-xss
revision: 1
activity_at: "2026-11-09T11:42:48Z"
title: 'Nickboss WordPress File Upload: Stored Cross-site Scripting (CVE-2026-123460)'
slug: 2026-11-09-wp-file-upload-xss
description: The Nickboss WordPress File Upload plugin (versions n/a through 5.2.2) contains a Stored Cross-site Scripting (XSS) vulnerability due to improper neutralization of input during web page generation.
date: "2026-11-09T11:42:48Z"
type: advisory
types:
  - advisory
severities:
  - medium
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
  - WordPress File Upload (n/a through 5.2.2)
cves:
  - id: CVE-2026-123460
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123460
---

The Nickboss WordPress File Upload plugin (wp-file-upload) contains an "Improper Neutralization of Input During Web Page Generation" vulnerability, categorized as Stored Cross-site Scripting (XSS). This issue affects versions from n/a through 5.2.2.
