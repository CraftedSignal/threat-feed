---
brief_id: brief-2026-10-29-python-markdown2-dos
event_id: brief-2026-10-29-python-markdown2-dos
revision: 1
activity_at: "2026-10-29T01:00:00Z"
title: 'python-markdown2: Denial of Service via unclosed inline links (CVE-2026-118694)'
slug: 2026-10-python-markdown2-dos
description: python-markdown2 through 2.5.5 contains a denial of service vulnerability that allows remote users to exhaust CPU by submitting Markdown with unclosed inline link destinations.
date: "2026-10-29T01:00:00Z"
type: advisory
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
products:
  - python-markdown2 (<= 2.5.5)
cves:
  - id: CVE-2026-118694
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118694
---

python-markdown2 through 2.5.5 contains a denial of service vulnerability. Attackers can submit repeated '[a](' or '![a](' sequences, causing the _find_balanced function to rescan the remaining document for each link and consume quadratic CPU time.
