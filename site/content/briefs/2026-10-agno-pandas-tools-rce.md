---
brief_id: brief-2026-10-29-agno-pandas-tools-rce
event_id: brief-2026-10-29-agno-pandas-tools-rce
revision: 1
activity_at: "2026-10-29T15:37:37Z"
title: 'Agno: Unsafe reflection in PandasTools (CVE-2026-119050)'
slug: 2026-10-agno-pandas-tools-rce
description: Agno through 3.1.11 contains an unsafe reflection vulnerability in PandasTools that allows attackers to invoke arbitrary pandas functions via prompt injection.
date: "2026-10-29T15:37:37Z"
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
cpes:
  - cpe:2.3:a:agno:agno:*:*:*:*:*:*:*:*
vendors:
  - Agno
products:
  - Agno (<= 3.1.11)
cves:
  - id: CVE-2026-119050
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119050
---

Agno through 3.1.11 contains an unsafe reflection vulnerability in PandasTools that allows attackers to invoke arbitrary pandas functions by supplying model-controlled function names to `getattr()`. Attackers can use prompt injection to make the agent call `pandas.read_pickle` on attacker-controlled paths for code execution, or call other readers to read local files.
