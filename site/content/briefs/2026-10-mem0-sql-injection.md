---
brief_id: brief-2026-10-22-mem0-sql-injection
event_id: brief-2026-10-22-mem0-sql-injection
revision: 1
activity_at: "2026-10-22T14:16:49Z"
title: 'mem0: SQL injection in Databricks vector store (CVE-2026-115324)'
slug: 2026-10-mem0-sql-injection
description: mem0 versions 0.1.117 before 1.0.8 contain an SQL injection vulnerability in mem0/vector_stores/databricks.py that allows attackers to execute injected SQL on the configured Databricks SQL warehouse by influencing stored memory content.
date: "2026-10-22T14:16:49Z"
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
  - mem0 (0.1.117 before 1.0.8)
cves:
  - id: CVE-2026-115324
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115324
---

CVE-2026-115324 is a SQL injection vulnerability in the mem0 library (versions 0.1.117 before 1.0.8). The flaw exists in `mem0/vector_stores/databricks.py` due to unescaped string interpolation in `insert()` and `update()` operations. Attackers can supply crafted memory text, metadata, or message names to execute injected SQL on the configured Databricks SQL warehouse.
