---
brief_id: brief-2026-11-09-confection-wordpress-cable-rce
event_id: brief-2026-11-09-confection-wordpress-cable-rce
revision: 2
activity_at: "2026-11-13T05:03:02Z"
revision_history:
  - revision: 2
    at: "2026-11-13T05:03:02Z"
    checksum: sha256:0d3755224549ee8233078e5398a2f621f28bba6a426b3fb7937af9399fbecf2b
    summary: poc_available
    changed_fields:
      - claim_state
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=363378F3-01C3-5E4B-BBF7-2D1478F0DAA3&utm_source=rss&utm_medium=rss
title: 'Confection WordPress Cable: Unauthenticated Remote Code Execution (CVE-2026-115252)'
slug: 2026-11-confection-wordpress-cable-rce
description: The Confection WordPress Cable plugin (versions 0.4.0 to 0.4.7) is vulnerable to unauthenticated remote code execution due to a lack of capability and nonce checks.
date: "2026-11-09T11:40:25Z"
lastmod: "2026-11-13T05:02:00Z"
type: advisory
claim_state: <nil>
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
  - cpe:2.3:a:confection:wordpress_cable:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=363378F3-01C3-5E4B-BBF7-2D1478F0DAA3&utm_source=rss&utm_medium=rss
vendors:
  - Confection
products:
  - WordPress Cable (0.4.0 - 0.4.7)
cves:
  - id: CVE-2026-115252
    cvss: 10
    epss: 0.00418
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115252
  - https://sploitus.com/exploit?id=363378F3-01C3-5E4B-BBF7-2D1478F0DAA3&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-13T05:02:00Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=363378F3-01C3-5E4B-BBF7-2D1478F0DAA3&utm_source=rss&utm_medium=rss
---

The Confection WordPress Cable WordPress plugin (versions 0.4.0 to 0.4.7) does not perform capability or nonce checks before saving its settings. The plugin writes settings, unmodified, into a standalone PHP file that it then serves, allowing unauthenticated users to execute arbitrary PHP code on the server.
