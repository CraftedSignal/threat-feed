---
title: threat-fixture triage fixture
slug: threat-fixture
description: Verifies mobile triage and append-only revision rendering.
date: "2026-10-19T08:00:00Z"
lastmod: "2026-10-20T08:00:00Z"
type: threat
types: [threat]
severities: [high]
brief_id: brief-threat-fixture
event_id: event-threat-fixture
revision: 2
activity_at: "2026-10-20T08:00:00Z"
products: ["Fixture Product (1.0)"]
affected_os: [Linux]
references: [https://example.com/advisory]
exploitation_evidence:
  status: confirmed_active
  source_url: https://example.com/advisory
  observed_at: "2026-10-20T07:30:00Z"
  confidence: high
cves:
  - id: CVE-2026-1234
    kev_status: "unknown"
rules_count: 2
ioc_counts:
  domain: 1
action_plan:
  priority: elevated
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: validated
revision_history:
  - revision: 1
    at: "2026-10-19T08:00:00Z"
    checksum: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    summary: Initial publication.
    changed_fields: [content]
    source_urls: [https://example.com/advisory]
  - revision: 2
    at: "2026-10-20T08:00:00Z"
    checksum: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    summary: Confirmed active exploitation.
    changed_fields: [exploitation_evidence]
    source_urls: [https://example.com/advisory]
---

Fixture body.

