---
brief_id: brief-2026-10-21-weforms-path-traversal
event_id: brief-2026-10-21-weforms-path-traversal
revision: 1
activity_at: "2026-10-21T16:08:28Z"
title: 'Bold Grid weForms: Path Traversal (CVE-2026-111833)'
slug: 2026-10-weforms-path-traversal
description: The Bold Grid weForms plugin is affected by an Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) vulnerability.
date: "2026-10-21T16:08:28Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:bold_grid:weforms:*:*:*:*:*:*:*:*
vendors:
  - Bold Grid
products:
  - weForms (n/a through 1.6.28)
cves:
  - id: CVE-2026-111833
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111833
---

CVE-2026-111833 identifies a Path Traversal vulnerability in Bold Grid weForms, affecting versions from n/a through 1.6.28.
