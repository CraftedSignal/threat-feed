---
brief_id: brief-2026-10-29-frappe-traversal
event_id: brief-2026-10-29-frappe-traversal
revision: 2
activity_at: "2026-10-29T20:38:27Z"
revision_history:
  - revision: 2
    at: "2026-10-29T20:38:27Z"
    checksum: sha256:8db3c00037c8e01129ea9af72ae597876aabc808416bf2cfa9c5f92d84bbd100
    summary: added CVE-2026-119144
    changed_fields:
      - affected_products
      - affected_vendors
      - cpes
      - cves
      - lastmod
      - priority_signals
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-119144
title: 'Frappe Framework: Path traversal vulnerability (CVE-2026-119145)'
slug: 2026-10-frappe-traversal
description: Frappe contains a path traversal vulnerability in its file-upload handling that can allow authenticated attackers to achieve remote code execution.
date: "2026-10-29T18:45:35Z"
lastmod: "2026-10-29T20:37:25Z"
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
  - cpe:2.3:a:frappe:framework:*:*:*:*:*:*:*:*
vendors:
  - Frappe
products:
  - Frappe Framework (< 15.121.0, 16.x < 16.34.0)
  - Frappe Framework (< 15.111.0, 16.x < 16.21.0)
cves:
  - id: CVE-2026-119145
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-119144
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119145
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119144
updates:
  - at: "2026-10-29T20:37:25Z"
    level: L2
    summary: added CVE-2026-119144
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-119144
---

Frappe before 15.121.0 and 16.x before 16.34.0 contains a path traversal vulnerability because file-upload handling does not validate the destination path before writing to disk. Authenticated attackers can upload crafted files to locations outside the intended storage directory to achieve remote code execution on the server.
