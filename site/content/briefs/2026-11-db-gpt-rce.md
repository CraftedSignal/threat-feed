---
brief_id: brief-2026-11-05-db-gpt-rce
event_id: brief-2026-11-05-db-gpt-rce
revision: 2
activity_at: "2026-11-05T16:33:05Z"
revision_history:
  - revision: 2
    at: "2026-11-05T16:33:05Z"
    checksum: sha256:f949e26c35f885b03d3914b659ddd694e9e2c7c55157937044cec926ba77d516
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-123018&utm_source=rss&utm_medium=rss
title: 'eosphoros-ai DB-GPT: Code injection vulnerability (CVE-2026-123018)'
slug: 2026-11-db-gpt-rce
description: A code injection vulnerability in the DB-GPT execute_code function allows for remote code execution, and public exploit code is available.
date: "2026-11-05T12:58:18Z"
lastmod: "2026-11-05T16:32:30Z"
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
cpes:
  - cpe:2.3:a:eosphoros_ai:db_gpt:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-123018&utm_source=rss&utm_medium=rss
vendors:
  - eosphoros-ai
products:
  - DB-GPT (<= 0.8.2)
cves:
  - id: CVE-2026-123018
    cvss: 8.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123018
  - https://sploitus.com/exploit?id=CVE-2026-123018&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-05T16:32:30Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-123018&utm_source=rss&utm_medium=rss
---

A security flaw (CVE-2026-123018) has been identified in eosphoros-ai DB-GPT versions up to 0.8.2. The vulnerability resides in the `execute_code` function within the `code_utils.py` file of the `CodeAction` component. This flaw allows for code injection and can be initiated remotely. Public exploit code for this vulnerability is available. The project was notified via an issue report but has not yet responded.
