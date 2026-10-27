---
brief_id: brief-2026-10-27-dell-powerprotect-path-traversal
event_id: brief-2026-10-27-dell-powerprotect-path-traversal
revision: 1
activity_at: "2026-10-27T15:51:38Z"
title: 'Dell PowerProtect Data Domain Virtual Edition: Path Traversal (CVE-2026-94346)'
slug: 2026-10-dell-powerprotect-path-traversal
description: Dell PowerProtect Data Domain Virtual Edition contains a path traversal vulnerability that could allow a high-privileged remote attacker to perform command execution.
date: "2026-10-27T15:51:38Z"
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
  - cpe:2.3:a:dell:powerprotect_data_domain_virtual_edition:*:*:*:*:*:*:*:*
vendors:
  - Dell
products:
  - PowerProtect Data Domain Virtual Edition (7.7.1.0-8.7)
  - PowerProtect Data Domain Virtual Edition (7.13.1.0-7.13.1.70)
  - PowerProtect Data Domain Virtual Edition (8.3.1.0-8.3.1.30)
  - PowerProtect Data Domain Virtual Edition (8.6.1.0-8.6.1.10)
cves:
  - id: CVE-2026-94346
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94346
---

Dell PowerProtect Data Domain Virtual Edition versions 7.7.1.0 through 8.7, 7.13.1.0 through 7.13.1.70, 8.3.1.0 through 8.3.1.30, and 8.6.1.0 through 8.6.1.10 contain a Path Traversal vulnerability. A high-privileged attacker with remote access could potentially exploit this to achieve command execution.
