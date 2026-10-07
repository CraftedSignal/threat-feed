---
title: SQL Injection in Payload CMS SQLite and Postgres Adapters
slug: 2026-10-payload-sql-injection
description: An improper input sanitization vulnerability in Payload CMS database adapters allows attackers with collection access to execute SQL injection attacks via JSON and block fields.
date: "2026-10-07T22:49:08Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Payload
products:
  - '@payloadcms/db-sqlite (< 3.90.0, >= 4.0.0-canary.0 < 4.0.0-canary.34)'
  - '@payloadcms/db-d1-sqlite (< 3.90.0, >= 4.0.0-canary.0 < 4.0.0-canary.34)'
  - '@payloadcms/db-postgres (< 3.73.0)'
  - '@payloadcms/db-vercel-postgres (< 3.73.0)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker who has read plus create or update access to a collection can submit a request that includes a SQL injection targeting a specific field path shape and operators.
    confidence_band: high
cves:
  - id: CVE-2026-105856
references:
  - https://github.com/advisories/GHSA-pj7x-6wpf-pgvp
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105856
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade @payloadcms/db-sqlite, @payloadcms/db-d1-sqlite, @payloadcms/db-postgres, and @payloadcms/db-vercel-postgres to version 3.90.0 or 4.0.0-canary.34.
      owner: IT Operations
      addresses: CVE-2026-105856
      evidence: Users should upgrade Payload packages to >= 3.90.0 or >= 4.0.0-canary.34.
---

Payload CMS database adapters for SQLite and Postgres contain a SQL injection vulnerability identified as CVE-2026-105856. The flaw exists in the query processing logic when interacting with collections containing 'json' fields or 'blocks' fields configured with 'blocksAsJSON: true'. An attacker who possesses read, create, or update access to such a collection can submit specially crafted requests containing malicious operators or path shapes. By exploiting this insufficient sanitization of query inputs within the database adapter layers, an attacker may be able to manipulate database queries to bypass filters or extract unauthorized data. The vulnerability impacts users of @payloadcms/db-sqlite, @payloadcms/db-d1-sqlite, @payloadcms/db-postgres, and @payloadcms/db-vercel-postgres. Defenders should prioritize upgrading to version 3.90.0 or 4.0.0-canary.34 to remediate this vulnerability.

## Impact

Successful exploitation allows an authenticated attacker to inject arbitrary SQL commands into the backend database. This could lead to unauthorized data exfiltration, modification of collection contents, or potential service disruption. The risk is constrained to environments where attackers have at least read access to collections configured with JSON-based fields.

## Recommendation

- Upgrade affected Payload CMS database adapter packages immediately to version 3.90.0 or 4.0.0-canary.34.
- Audit logs for unexpected database query patterns, specifically focusing on POST requests to API endpoints that handle collection creation or updates containing nested JSON payloads.
- Review collection schemas to identify usage of 'json' fields or 'blocks' fields with 'blocksAsJSON: true' and apply least-privilege access controls to collections utilizing these field types until patches are applied.
