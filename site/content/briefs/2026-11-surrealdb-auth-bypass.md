---
brief_id: brief-2026-11-03-surrealdb-auth-bypass
event_id: brief-2026-11-03-surrealdb-auth-bypass
revision: 2
activity_at: "2026-11-03T16:15:50Z"
revision_history:
  - revision: 2
    at: "2026-11-03T16:15:50Z"
    checksum: sha256:c37423b2194f27b3dfde5161410f9a0a0b641abf460161a2eec70a323a8dba4f
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-121419&utm_source=rss&utm_medium=rss
title: 'SurrealDB: Improper MCP authentication vulnerability (CVE-2026-121419)'
slug: 2026-11-surrealdb-auth-bypass
description: SurrealDB versions 3.1.0 before 3.3.0 contain an improper authentication vulnerability in the MCP BoundSubject fingerprint.
date: "2026-11-03T15:59:48Z"
lastmod: "2026-11-03T16:14:49Z"
type: advisory
claim_state: <nil>
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
  - https://sploitus.com/exploit?id=CVE-2026-121419&utm_source=rss&utm_medium=rss
products:
  - SurrealDB (3.1.0 up to, but not including, 3.3.0)
cves:
  - id: CVE-2026-121419
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121419
  - https://sploitus.com/exploit?id=CVE-2026-121419&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-03T16:14:49Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-121419&utm_source=rss&utm_medium=rss
---

SurrealDB from 3.1.0 before 3.3.0 contains an improper authentication vulnerability where the MCP BoundSubject fingerprint uses the access method name instead of per-user identity for JWT/Bearer access. Attackers with a valid low-privilege token for the same access method and a victim's mcp-session-id can hijack the session and execute MCP tools with the victim's roles and permissions.
