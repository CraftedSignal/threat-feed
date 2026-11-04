---
brief_id: brief-2026-11-04-linksys-e5600-oob-write
event_id: brief-2026-11-04-linksys-e5600-oob-write
revision: 2
activity_at: "2026-11-04T10:43:15Z"
revision_history:
  - revision: 2
    at: "2026-11-04T10:43:15Z"
    checksum: sha256:391193ad4d1aabbcf501aaaf33fd205900115eb16e77a50e8f9d0b687da3bd32
    summary: severity → critical; added CVE-2026-121615
    changed_fields:
      - cves
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - severity
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-121615
title: Linksys E5600 Out-of-Bounds Write (CVE-2026-121617)
slug: 2026-11-linksys-e5600-oob-write
description: A security flaw in Linksys E5600 version 1.1.0.26 allows for a remote out-of-bounds write via the init_multipart function.
date: "2026-11-04T08:39:42Z"
lastmod: "2026-11-04T10:41:45Z"
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
  - cpe:2.3:a:linksys:e5600:*:*:*:*:*:*:*:*
vendors:
  - Linksys
products:
  - E5600 (1.1.0.26)
cves:
  - id: CVE-2026-121617
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-121615
    cvss: 10
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121617
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121615
updates:
  - at: "2026-11-04T10:41:45Z"
    level: L3
    summary: severity → critical; added CVE-2026-121615
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-121615
---

A security flaw (CVE-2026-121617) exists in Linksys E5600 1.1.0.26. The vulnerability affects the init_multipart function of the /cgi-bin/upload_fw.cgi file in the Header Parser component. The manipulation results in an out-of-bounds write. The attack may be launched remotely. Public exploit code is available. The vendor was contacted but did not respond. This vulnerability only affects products that are no longer supported by the maintainer.
