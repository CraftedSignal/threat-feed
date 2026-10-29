---
brief_id: brief-2026-10-23-pillow-vulnerabilities
event_id: brief-2026-10-23-pillow-vulnerabilities
revision: 3
activity_at: "2026-10-29T19:55:25Z"
revision_history:
  - revision: 2
    at: "2026-10-23T14:58:59Z"
    checksum: sha256:ed39559427fdd91b760fa45b0379d8241666117be2ee030bba748ffb8335d193
    summary: poc_available
    changed_fields:
      - affected_products
      - affected_vendors
      - cpes
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=50A08BE3-5B9D-56F1-AB76-8E844B7BA00D&utm_source=rss&utm_medium=rss
  - revision: 3
    at: "2026-10-29T19:55:25Z"
    checksum: sha256:37c974a2d2957d19258b10ef3e7f7325f93ef818cac8ee551f976ce2e2d670c9
    summary: new product
    changed_fields:
      - affected_products
      - claim_state
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-mrfp-p49p-3hf2
title: 'Pillow: Remote Code Execution and Memory Vulnerabilities'
slug: 2026-10-pillow-vulnerabilities
description: Pillow, a Python image library, contains vulnerabilities that allow for remote code execution or process crashes through the processing of crafted image files or filenames.
date: "2026-10-23T10:36:51Z"
lastmod: "2026-10-29T19:52:56Z"
type: advisory
claim_state: <nil>
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
cpes:
  - cpe:2.3:a:python:pillow:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=50A08BE3-5B9D-56F1-AB76-8E844B7BA00D&utm_source=rss&utm_medium=rss
vendors:
  - Python
products:
  - Pillow (< 13.0.0)
  - Pillow (>= 5.1.0, <= 12.3.0)
cves:
  - id: CVE-2026-112393
    cvss: 9.8
    epss: 0.01019
    kev_status: "false"
  - id: CVE-2026-112403
    cvss: 9.8
    epss: 0.00945
    kev_status: "false"
  - id: CVE-2026-112900
    cvss: 9.8
    epss: 0.01303
    kev_status: "false"
references:
  - https://thehackernews.com/2026/10/critical-flaw-in-pythons-popular-pillow.html
  - https://sploitus.com/exploit?id=50A08BE3-5B9D-56F1-AB76-8E844B7BA00D&utm_source=rss&utm_medium=rss
  - https://github.com/advisories/GHSA-mrfp-p49p-3hf2
updates:
  - at: "2026-10-23T14:57:44Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=50A08BE3-5B9D-56F1-AB76-8E844B7BA00D&utm_source=rss&utm_medium=rss
  - at: "2026-10-29T19:52:56Z"
    level: L1
    summary: new product
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-mrfp-p49p-3hf2
---

Pillow contains security vulnerabilities that can be triggered by processing crafted image files or specific filenames. One flaw, CVE-2026-112900, involves the library passing an attacker-controlled filename to Ghostscript when opening EPS images, which can lead to operating system command execution. Other vulnerabilities include memory buffer overflows in JPEG and TIFF processing. Pillow maintainers released version 13.0.0 to address these issues.
