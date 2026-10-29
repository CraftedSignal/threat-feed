---
brief_id: brief-2026-10-27-dell-powerprotect-path-traversal
event_id: brief-2026-10-27-dell-powerprotect-path-traversal
revision: 2
activity_at: "2026-10-29T20:15:56Z"
revision_history:
  - revision: 2
    at: "2026-10-29T20:15:56Z"
    checksum: sha256:971c9966452b7333d0175056974c07d772a0911e56bb76eb64bf7eeea7a18a33
    summary: added CVE-2026-94347
    changed_fields:
      - affected_products
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-94347
title: 'Dell PowerProtect Data Domain Virtual Edition: Path Traversal (CVE-2026-94346)'
slug: 2026-10-dell-powerprotect-path-traversal
description: Dell PowerProtect Data Domain Virtual Edition contains a path traversal vulnerability that could allow a high-privileged remote attacker to perform command execution.
date: "2026-10-27T15:51:38Z"
lastmod: "2026-10-29T20:13:56Z"
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
  - PowerProtect Data Domain Virtual Edition (Feature Release 7.7.1.0 - 8.7)
  - PowerProtect Data Domain Virtual Edition (LTS2024 7.13.1.0 - 7.13.1.70)
  - PowerProtect Data Domain Virtual Edition (LTS2025 8.3.1.0 - 8.3.1.30)
  - PowerProtect Data Domain Virtual Edition (LTS2026 8.6.1.0 - 8.6.1.10)
cves:
  - id: CVE-2026-94346
    cvss: 7.2
    kev_status: "false"
  - id: CVE-2026-94347
    cvss: 7.2
    epss: 0.00295
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94346
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94347
updates:
  - at: "2026-10-29T20:13:56Z"
    level: L2
    summary: added CVE-2026-94347
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-94347
---

Dell PowerProtect Data Domain Virtual Edition versions 7.7.1.0 through 8.7, 7.13.1.0 through 7.13.1.70, 8.3.1.0 through 8.3.1.30, and 8.6.1.0 through 8.6.1.10 contain a Path Traversal vulnerability. A high-privileged attacker with remote access could potentially exploit this to achieve command execution.
