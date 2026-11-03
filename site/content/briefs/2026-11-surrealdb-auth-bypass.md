---
brief_id: brief-2026-11-03-surrealdb-auth-bypass
event_id: brief-2026-11-03-surrealdb-auth-bypass
revision: 1
activity_at: "2026-11-03T15:59:48Z"
title: 'SurrealDB: Improper MCP authentication vulnerability (CVE-2026-121419)'
slug: 2026-11-surrealdb-auth-bypass
description: SurrealDB versions 3.1.0 before 3.3.0 contain an improper authentication vulnerability in the MCP BoundSubject fingerprint.
date: "2026-11-03T15:59:48Z"
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
products:
  - SurrealDB (3.1.0 up to, but not including, 3.3.0)
cves:
  - id: CVE-2026-121419
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121419
---

SurrealDB from 3.1.0 before 3.3.0 contains an improper authentication vulnerability where the MCP BoundSubject fingerprint uses the access method name instead of per-user identity for JWT/Bearer access. Attackers with a valid low-privilege token for the same access method and a victim's mcp-session-id can hijack the session and execute MCP tools with the victim's roles and permissions.
