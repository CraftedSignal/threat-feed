---
brief_id: brief-2026-10-26-hashicorp-consul-auth-bypass
event_id: brief-2026-10-26-hashicorp-consul-auth-bypass
revision: 2
activity_at: "2026-10-26T21:06:54Z"
revision_history:
  - revision: 2
    at: "2026-10-26T21:06:54Z"
    checksum: sha256:fe1c4cfe3d4f0ba1e0d9ed175d051103183a6c0ff94e0bfd42cae8a94dc8a0c8
    summary: poc_available
    changed_fields:
      - affected_vendors
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-105608&utm_source=rss&utm_medium=rss
title: 'HashiCorp Consul: Authorization bypass in service mesh proxy registration (CVE-2026-105608)'
slug: 2026-10-hashicorp-consul-auth-bypass
description: An authorization bypass in HashiCorp Consul and Consul Enterprise service mesh proxy registration allows users with service write permission to apply Envoy escape-hatch configuration without the required mesh write permission.
date: "2026-10-26T19:45:02Z"
lastmod: "2026-10-26T21:05:47Z"
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
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-105608&utm_source=rss&utm_medium=rss
vendors:
  - HashiCorp
cves:
  - id: CVE-2026-105608
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105608
  - https://sploitus.com/exploit?id=CVE-2026-105608&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-10-26T21:05:47Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-105608&utm_source=rss&utm_medium=rss
---

HashiCorp Consul and Consul Enterprise are vulnerable to an authorization bypass in service mesh proxy registration (CVE-2026-105608). This vulnerability allows a user with service write permission to apply Envoy escape-hatch configuration without the required mesh write permission. This issue is resolved in Consul Community Edition 2.1.0 and Consul Enterprise 2.1.0 and 1.21.19.
