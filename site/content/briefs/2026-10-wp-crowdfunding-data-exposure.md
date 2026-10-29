---
brief_id: brief-2026-10-29-wp-crowdfunding-data-exposure
event_id: brief-2026-10-29-wp-crowdfunding-data-exposure
revision: 2
activity_at: "2026-10-29T17:41:25Z"
revision_history:
  - revision: 2
    at: "2026-10-29T17:41:25Z"
    checksum: sha256:1a15c4d7beab63d4d6e15189a51e48efb35181517814ec9d919e933c794bb10c
    summary: added CVE-2026-42692
    changed_fields:
      - cves
      - lastmod
      - references
      - tags
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-42692
title: 'WP Crowdfunding: Unauthenticated sensitive data exposure (CVE-2026-118083)'
slug: 2026-10-wp-crowdfunding-data-exposure
description: WP Crowdfunding versions 2.2.2 and earlier contain an unauthenticated sensitive data exposure vulnerability.
date: "2026-10-29T17:37:22Z"
lastmod: "2026-10-29T17:39:36Z"
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
tags:
  - web-application
  - data-exposure
  - wordpress
  - xss
  - vulnerability
products:
  - WP Crowdfunding (<= 2.2.2)
cves:
  - id: CVE-2026-118083
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-42692
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118083
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42692
updates:
  - at: "2026-10-29T17:39:36Z"
    level: L2
    summary: added CVE-2026-42692
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-42692
---

CVE-2026-118083 identifies an unauthenticated sensitive data exposure vulnerability in WP Crowdfunding versions 2.2.2 and earlier. The vulnerability has a CVSS v3.1 base score of 7.5.
