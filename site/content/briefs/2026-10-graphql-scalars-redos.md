---
brief_id: brief-2026-10-24-graphql-scalars-redos
event_id: brief-2026-10-24-graphql-scalars-redos
revision: 2
activity_at: "2026-10-29T00:15:12Z"
revision_history:
  - revision: 2
    at: "2026-10-29T00:15:12Z"
    checksum: sha256:e69415fa161ba3177c3ff8fa814d9a7de449c9812c62651371aa304f8da56acf
    summary: poc_available
    changed_fields:
      - affected_vendors
      - claim_state
      - cves
      - has_poc
      - lastmod
      - references
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-x8rm-f576-gq67
title: 'GraphQL Scalars: ReDoS via GraphQLPhoneNumber (CVE-2026-115887)'
slug: 2026-10-graphql-scalars-redos
description: The GraphQLPhoneNumber scalar in the GraphQL Scalars library uses ambiguous nested digit quantifiers that backtrack exponentially, allowing unauthenticated requests to block the Node.js event loop and stall the server process.
date: "2026-10-24T00:03:00Z"
lastmod: "2026-10-29T00:12:10Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
has_poc: true
vendors:
  - graphql-scalars
cves:
  - id: CVE-2026-115887
    cvss: 7.5
    epss: 0.00408
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115887
  - https://github.com/advisories/GHSA-x8rm-f576-gq67
updates:
  - at: "2026-10-29T00:12:10Z"
    level: L2
    summary: poc_available
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-x8rm-f576-gq67
---

CVE-2026-115887 involves a vulnerability in `src/scalars/PhoneNumber.ts` within the GraphQL Scalars library. The scalar uses ambiguous nested digit quantifiers that cause exponential backtracking when a value contains a sequence of digits followed by a character that triggers a match failure. Because this occurs during document validation (parseLiteral) or variable coercion (parseValue) before authentication or authorization, unauthenticated requests can block the Node.js event loop. The `serialize` function is also affected.
