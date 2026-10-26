---
brief_id: brief-2026-10-26-consul-k8s-acl-bypass
event_id: brief-2026-10-26-consul-k8s-acl-bypass
revision: 2
activity_at: "2026-10-26T21:06:54Z"
revision_history:
  - revision: 2
    at: "2026-10-26T21:06:54Z"
    checksum: sha256:e43d3548f0c4460db89fa0b47ef2498c9186073cc18c6b524a04c2f3305d51fa
    summary: poc_available
    changed_fields:
      - affected_vendors
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-110720&utm_source=rss&utm_medium=rss
title: 'HashiCorp Consul-k8s: Cross-namespace authorization bypass (CVE-2026-110720)'
slug: 2026-10-consul-k8s-acl-bypass
description: Consul-k8s versions 0.42.0 and later are vulnerable to a cross-namespace authorization bypass in component ACL binding rules that may allow an attacker to obtain elevated Consul privileges.
date: "2026-10-26T19:45:45Z"
lastmod: "2026-10-26T21:05:44Z"
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
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-110720&utm_source=rss&utm_medium=rss
vendors:
  - HashiCorp
cves:
  - id: CVE-2026-110720
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110720
  - https://sploitus.com/exploit?id=CVE-2026-110720&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-10-26T21:05:44Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-110720&utm_source=rss&utm_medium=rss
---

Consul-k8s versions 0.42.0 and later are vulnerable to a cross-namespace authorization bypass in component ACL binding rules that may allow an attacker to obtain elevated Consul privileges. This vulnerability is identified as CVE-2026-110720 and has a CVSS v3.1 base score of 9.9. This vulnerability is fixed in consul-k8s versions 2.1.0 and 1.8.18.
