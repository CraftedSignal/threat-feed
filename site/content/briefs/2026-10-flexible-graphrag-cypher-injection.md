---
brief_id: brief-2026-10-28-flexible-graphrag-cypher-injection
event_id: brief-2026-10-28-flexible-graphrag-cypher-injection
revision: 1
activity_at: "2026-10-28T18:09:54Z"
title: 'flexible-graphrag: Cypher injection in FalkorDB adapter'
slug: 2026-10-flexible-graphrag-cypher-injection
description: The flexible-graphrag Python package (FalkorDB adapter) is vulnerable to Cypher injection due to a flawed string-escaping implementation and the use of string interpolation for query construction.
date: "2026-10-28T18:09:54Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
cves:
  - id: CVE-2026-114510
    cvss: 7.1
    epss: 0.00241
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-vqrg-773h-4wxc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114510
---

The `_escape()` function in the `flexible-graphrag` FalkorDB adapter contains an ordering error that fails to neutralize single quotes. Because the adapter uses f-string interpolation for Cypher queries, untrusted document content containing malicious payloads can escape string literals and inject arbitrary Cypher clauses. Additionally, node labels and relationship types are interpolated without escaping. Exploitation can result in unauthorized graph data modification or deletion.
