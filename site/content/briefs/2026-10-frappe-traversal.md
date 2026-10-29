---
brief_id: brief-2026-10-29-frappe-traversal
event_id: brief-2026-10-29-frappe-traversal
revision: 1
activity_at: "2026-10-29T18:45:35Z"
title: 'Frappe Framework: Path traversal vulnerability (CVE-2026-119145)'
slug: 2026-10-frappe-traversal
description: Frappe contains a path traversal vulnerability in its file-upload handling that can allow authenticated attackers to achieve remote code execution.
date: "2026-10-29T18:45:35Z"
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
  - Frappe Framework (< 15.121.0, 16.x < 16.34.0)
cves:
  - id: CVE-2026-119145
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119145
---

Frappe before 15.121.0 and 16.x before 16.34.0 contains a path traversal vulnerability because file-upload handling does not validate the destination path before writing to disk. Authenticated attackers can upload crafted files to locations outside the intended storage directory to achieve remote code execution on the server.
