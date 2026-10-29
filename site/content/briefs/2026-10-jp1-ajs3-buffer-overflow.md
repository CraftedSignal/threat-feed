---
brief_id: brief-2026-10-29-jp1-ajs3-buffer-overflow
event_id: brief-2026-10-29-jp1-ajs3-buffer-overflow
revision: 1
activity_at: "2026-10-29T20:13:23Z"
title: Heap-based Buffer Overflow in JP1/Automatic Job Management System 3 (CVE-2026-76939)
slug: 2026-10-jp1-ajs3-buffer-overflow
description: A heap-based buffer overflow vulnerability has been identified in JP1/Automatic Job Management System 3.
date: "2026-10-29T20:13:23Z"
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
  - JP1/Automatic Job Management System 3 - Manager (11-00 to <13-50-31)
  - JP1/Automatic Job Management System 3 - Agent (11-00 to <13-50-31)
cves:
  - id: CVE-2026-76939
    cvss: 9.8
    epss: 0.00519
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76939
---

CVE-2026-76939 is a heap-based buffer overflow vulnerability affecting JP1/Automatic Job Management System 3 - Manager and JP1/Automatic Job Management System 3 - Agent. The affected versions for both include 11-00 through versions prior to 13-50-31. The vulnerability has a CVSS v3.1 base score of 9.8.
