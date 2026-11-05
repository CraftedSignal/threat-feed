---
brief_id: brief-2026-11-04-apache-openoffice-heap-overflow
event_id: brief-2026-11-04-apache-openoffice-heap-overflow
revision: 1
activity_at: "2026-11-04T18:50:28Z"
title: 'Apache OpenOffice: Heap buffer overflow in Draw component (CVE-2026-59267)'
slug: 2026-11-apache-openoffice-heap-overflow
description: A heap buffer overflow in the Draw component of Apache OpenOffice 4.1.16 and earlier can be triggered by a crafted DXF document, potentially causing a crash or memory corruption.
date: "2026-11-04T18:50:28Z"
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
  - cpe:2.3:a:apache:openoffice:*:*:*:*:*:*:*:*
products:
  - cpe:2.3:a:apache:openoffice:*:*:*:*:*:*:*:*
cves:
  - id: CVE-2026-59267
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-59267
---

A crafted DXF document causes a heap buffer overflow in the Draw component of Apache OpenOffice 4.1.16 and earlier. This vulnerability could cause an application crash or corruption of memory areas. Users are recommended to upgrade to version 4.1.17.
