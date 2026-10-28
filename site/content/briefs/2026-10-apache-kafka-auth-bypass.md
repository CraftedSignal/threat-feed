---
brief_id: brief-2026-10-28-apache-kafka-auth-bypass
event_id: brief-2026-10-28-apache-kafka-auth-bypass
revision: 2
activity_at: "2026-10-28T19:24:42Z"
revision_history:
  - revision: 2
    at: "2026-10-28T19:24:42Z"
    checksum: sha256:31fbef95a7d47b2f87ab5681f99980fe6640c1afb8c8f294aaae76bb14ce1585
    summary: poc_available
    changed_fields:
      - affected_vendors
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-115644&utm_source=rss&utm_medium=rss
title: 'Apache Kafka: Admin REST API authentication bypass (CVE-2026-115644)'
slug: 2026-10-apache-kafka-auth-bypass
description: Apache Kafka Connect contains an authentication bypass vulnerability affecting the admin REST API when admin.listeners is configured with a separate listener from the main listeners property.
date: "2026-10-28T18:21:20Z"
lastmod: "2026-10-28T19:23:43Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-115644&utm_source=rss&utm_medium=rss
vendors:
  - Apache
cves:
  - id: CVE-2026-115644
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/422
  - https://sploitus.com/exploit?id=CVE-2026-115644&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-10-28T19:23:43Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-115644&utm_source=rss&utm_medium=rss
---

Apache Kafka Connect contains an authentication bypass vulnerability affecting the admin REST API. This occurs when the admin.listeners property is configured with a separate listener from the main listeners property.
