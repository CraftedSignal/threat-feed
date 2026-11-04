---
brief_id: brief-2026-11-04-linksys-e5600-oob-write
event_id: brief-2026-11-04-linksys-e5600-oob-write
revision: 1
activity_at: "2026-11-04T08:39:42Z"
title: Linksys E5600 Out-of-Bounds Write (CVE-2026-121617)
slug: 2026-11-linksys-e5600-oob-write
description: A security flaw in Linksys E5600 version 1.1.0.26 allows for a remote out-of-bounds write via the init_multipart function.
date: "2026-11-04T08:39:42Z"
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
  - cpe:2.3:a:linksys:e5600:*:*:*:*:*:*:*:*
vendors:
  - Linksys
products:
  - E5600 (1.1.0.26)
cves:
  - id: CVE-2026-121617
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121617
---

A security flaw (CVE-2026-121617) exists in Linksys E5600 1.1.0.26. The vulnerability affects the init_multipart function of the /cgi-bin/upload_fw.cgi file in the Header Parser component. The manipulation results in an out-of-bounds write. The attack may be launched remotely. Public exploit code is available. The vendor was contacted but did not respond. This vulnerability only affects products that are no longer supported by the maintainer.
