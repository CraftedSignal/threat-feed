---
brief_id: brief-2026-10-23-pillow-vulnerabilities
event_id: brief-2026-10-23-pillow-vulnerabilities
revision: 1
activity_at: "2026-10-23T10:36:51Z"
title: 'Pillow: Remote Code Execution and Memory Vulnerabilities'
slug: 2026-10-pillow-vulnerabilities
description: Pillow, a Python image library, contains vulnerabilities that allow for remote code execution or process crashes through the processing of crafted image files or filenames.
date: "2026-10-23T10:36:51Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: not_observed
  source_url: https://thehackernews.com/2026/10/critical-flaw-in-pythons-popular-pillow.html
  observed_at: "2026-10-23T00:00:00Z"
  confidence: high
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cves:
  - id: CVE-2026-112393
    epss: 0.00528
    kev_status: "false"
  - id: CVE-2026-112403
    epss: 0.00321
    kev_status: "false"
  - id: CVE-2026-112900
    epss: 0.00431
    kev_status: "false"
references:
  - https://thehackernews.com/2026/10/critical-flaw-in-pythons-popular-pillow.html
---

Pillow contains security vulnerabilities that can be triggered by processing crafted image files or specific filenames. One flaw, CVE-2026-112900, involves the library passing an attacker-controlled filename to Ghostscript when opening EPS images, which can lead to operating system command execution. Other vulnerabilities include memory buffer overflows in JPEG and TIFF processing. Pillow maintainers released version 13.0.0 to address these issues.
