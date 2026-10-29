---
brief_id: brief-2026-10-29-dynamic-qr-code-injection
event_id: brief-2026-10-29-dynamic-qr-code-injection
revision: 1
activity_at: "2026-10-29T18:43:06Z"
title: 'Dynamic QR Code - generator: PHP object injection (CVE-2026-116867)'
slug: 2026-10-dynamic-qr-code-injection
description: A contributor PHP object injection vulnerability exists in the Dynamic QR Code - generator WordPress plugin, affecting versions 1.0.1 and earlier.
date: "2026-10-29T18:43:06Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
cpes:
  - cpe:2.3:a:wordpress:dynamic_qr_code_generator:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - php
  - wordpress
vendors:
  - WordPress
products:
  - Dynamic QR Code - generator (<= 1.0.1)
cves:
  - id: CVE-2026-116867
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116867
---

CVE-2026-116867 identifies a contributor PHP object injection vulnerability in the Dynamic QR Code - generator plugin for WordPress, affecting all versions up to and including 1.0.1.
